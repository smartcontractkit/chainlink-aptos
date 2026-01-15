package deploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/common"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"

	"github.com/BurntSushi/toml"
	"github.com/docker/go-connections/nat"
	"github.com/go-resty/resty/v2"
	"github.com/rs/zerolog"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

type StdoutLogConsumer struct {
	lggr *zerolog.Logger
}

func (lc *StdoutLogConsumer) Accept(l testcontainers.Log) {
	lc.lggr.Debug().Msg(string(l.Content))
}

type TestContainer struct {
	Container testcontainers.Container
	Env       map[string]string
}

type Deployer struct {
	lggr          *zerolog.Logger
	containerLggr *StdoutLogConsumer
	Configs       *Configs
	Network       string
	Core          []*CoreClient
	Keystone      *Keystone
	Devnet        *DevnetClient
	Geth          *GethClient
	Postgres      *PostgresClient
	Contracts     *Contracts
}

type Configs struct {
	TestFolder        string
	NodesListFilePath string
	KeystoneWorkflow  string
}

type CoreClient struct {
	Name         string
	Client       *TestContainer
	Config       *CoreConfig
	Toml         string
	ExternalPort int
}

type DevnetClient struct {
	Client             *TestContainer
	Config             *DevnetConfig
	ExternalFaucetPort int
	ExternalHttpPort   int
	RestyClient        *resty.Client
}

type GethClient struct {
	Client           *TestContainer
	Config           *GethConfig
	ExternalHttpPort int
	ExternalWSPort   int
}

type PostgresClient struct {
	Client       *TestContainer
	Config       *PostgresConfig
	ExternalPort int
}

type Contracts struct {
	KeystoneAddress          string
	KeystoneSecondaryAddress string
	DataFeedsAddress         string
}

func New(lggr *zerolog.Logger) *Deployer {
	testFolder := fmt.Sprintf("%s/%s", scripts.Cache, scripts.GetRandomName(10))
	os.MkdirAll(testFolder, os.ModePerm)

	nodesListFile := fmt.Sprintf("%s/%s", testFolder, "NodesList.txt")

	network, err := createNetwork()
	if err != nil {
		panic("Could not create docker network")
	}
	lggr.Info().Msgf("Created docker network: %s", network)
	return &Deployer{
		lggr:          lggr,
		Network:       network,
		containerLggr: &StdoutLogConsumer{lggr: lggr},
		Keystone: &Keystone{
			NodesList:    nodesListFile,
			ArtefactsDir: testFolder,
		},
		Configs: &Configs{
			NodesListFilePath: nodesListFile,
			TestFolder:        testFolder,
		},
		Contracts: &Contracts{},
	}
}

func (d *Deployer) DeployPostgres() error {
	pgConfig, err := ValidatePostgres()

	if err != nil {
		return err
	}
	req := testcontainers.ContainerRequest{
		Image:        pgConfig.Image,
		ExposedPorts: pgConfig.Ports,
		WaitingFor:   wait.ForLog("listening on IPv4 address"),
		Networks:     []string{d.Network},
		NetworkAliases: map[string][]string{
			d.Network: {pgConfig.Name},
		},
		Env:  pgConfig.Env,
		Name: pgConfig.Name,
		Cmd: []string{
			"-c",
			"listen_addresses=*",
		},
	}
	container, err := d.StartContainer(req, d.lggr)
	if err != nil {
		return err

	}
	ctx := context.Background()
	externalPort, err := container.MappedPort(ctx, nat.Port(pgConfig.Ports[0]))
	if err != nil {
		return err

	}

	d.Postgres = &PostgresClient{
		Client:       &TestContainer{Container: container},
		Config:       pgConfig,
		ExternalPort: externalPort.Int(),
	}

	return nil
}

func (d *Deployer) DeployGeth() error {
	ctx := context.Background()
	gethConfig, err := ValidateGeth()
	d.Keystone.ChainId = gethConfig.ChainId

	if err != nil {
		return err
	}
	req := testcontainers.ContainerRequest{
		Image:        gethConfig.Image,
		ExposedPorts: gethConfig.Ports,
		WaitingFor:   wait.ForLog("Chain head was updated"),
		Networks:     []string{d.Network},
		Name:         "chainlink.geth",
		NetworkAliases: map[string][]string{
			d.Network: {gethConfig.Name},
		},
		Cmd: []string{
			"--dev",
			"--ipcdisable",
			"--http",
			"--http.vhosts=*",
			"--http.addr=0.0.0.0",
			fmt.Sprintf("--http.port=%s", gethConfig.Ports[1]),
			"--ws",
			"--ws.origins=*",
			"--ws.addr=0.0.0.0",
			fmt.Sprintf("--ws.port=%s", gethConfig.Ports[0]),
			"--allow-insecure-unlock",
			"--rpc.allow-unprotected-txs",
			"--http.corsdomain=*",
			"--vmdebug",
			"--dev.period=1",
			"--miner.gasprice=10",
		},
	}

	container, err := d.StartContainer(req, d.lggr)
	if err != nil {
		return err

	}

	externalHttpPort, err := container.MappedPort(ctx, nat.Port(gethConfig.Ports[1]))
	if err != nil {
		return err
	}

	externalWSPort, err := container.MappedPort(ctx, nat.Port(gethConfig.Ports[0]))
	if err != nil {
		return err
	}

	d.Geth = &GethClient{
		Client:           &TestContainer{Container: container},
		Config:           gethConfig,
		ExternalHttpPort: externalHttpPort.Int(),
		ExternalWSPort:   externalWSPort.Int(),
	}
	d.Keystone.GethHttpRPC = fmt.Sprintf("http://127.0.0.1:%d", externalHttpPort.Int())

	return nil
}

func (d *Deployer) DeployCore() error {
	coreConfig, err := ValidateCore()
	if err != nil {
		return err
	}
	d.Keystone.P2PPort = coreConfig.CoreP2PPort

	webserverPort, err := strconv.Atoi(coreConfig.Ports[0])
	if err != nil {
		return err
	}

	toml, err := d.loadCoreToml()
	if err != nil {
		return err
	}

	toml.Aptos[0].Workflow.ForwarderAddress = d.Contracts.KeystoneAddress

	var containers testcontainers.ParallelContainerRequest
	for i := 0; i < coreConfig.CoreNodeCount; i++ {
		containerName := fmt.Sprintf("%s-%d", coreConfig.Name, i)
		toml.WebServer.HTTPPort = webserverPort
		toml.Aptos[0].ChainID = d.Devnet.Config.ChainId
		toml.Aptos[0].Nodes[0].URL = d.Devnet.Config.HTTPRPC
		toml.EVM[0].ChainID = d.Geth.Config.ChainId
		toml.EVM[0].Nodes[0].Name = "node-geth-0"
		toml.EVM[0].Nodes[0].WSURL = d.Geth.Config.WSRPC
		toml.EVM[0].Nodes[0].HTTPURL = d.Geth.Config.HTTPRPC
		toml.P2P.V2.ListenAddresses = []string{fmt.Sprintf("0.0.0.0:%d", d.Keystone.P2PPort)}

		tomlString, _ := marshalCoreToml(toml)
		d.lggr.Debug().Msg(tomlString)

		dbName := fmt.Sprintf("core_test_%d", i)
		dbUrl := fmt.Sprintf("postgresql://%s:%s@127.0.0.1:%s/%s", d.Postgres.Config.Env["POSTGRES_USER"], d.Postgres.Config.Env["POSTGRES_PASSWORD"], d.Postgres.Config.Ports[0], d.Postgres.Config.Env["POSTGRES_DB"])
		d.lggr.Info().Msgf("Creating database core_test_%d in %s", i, containerName)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sc, resp, err := d.Postgres.Client.Container.Exec(ctx, []string{"psql", dbUrl, "-c", fmt.Sprintf("CREATE DATABASE %s;", dbName)})
		if err != nil {
			return err
		}

		if sc != 0 {
			return errors.New(fmt.Sprintf("Command returned non 0 status code, got %d", sc))
		}

		buf := new(strings.Builder)
		_, err = io.Copy(buf, resp)
		if err != nil {
			return err
		}

		d.lggr.Info().Msg(buf.String())

		dbUrl = fmt.Sprintf("postgresql://%s:%s@%s:%s/%s", d.Postgres.Config.Env["POSTGRES_USER"], d.Postgres.Config.Env["POSTGRES_PASSWORD"], d.Postgres.Config.Name, d.Postgres.Config.Ports[0], dbName)
		d.lggr.Info().Msgf("Database URL: %s", dbUrl)
		d.lggr.Info().Msgf("api_credentials: %s %s", coreConfig.Email, coreConfig.Password)
		req := testcontainers.ContainerRequest{
			Image:        coreConfig.Image,
			ExposedPorts: coreConfig.Ports,
			WaitingFor:   wait.ForLog("Listening and serving HTTP").WithStartupTimeout(10 * time.Minute),
			Networks:     []string{d.Network},
			NetworkAliases: map[string][]string{
				d.Network: {containerName},
			},

			Name: containerName,
			Env: map[string]string{
				"CL_CONFIG":            tomlString,
				"CL_DATABASE_URL":      fmt.Sprintf("%s?sslmode=disable", dbUrl),
				"CL_PASSWORD_KEYSTORE": "notastrongpassword",
				"CL_EVM_CMD":           "", // Disable LOOPP mode for EVM to enable ReplayFromBlock
			},
			Entrypoint: []string{"bash", "-c", fmt.Sprintf("echo -e \"%s\\n%s\" > /tmp/api_credentials && chainlink node start --api /tmp/api_credentials", coreConfig.Email, coreConfig.Password)},
		}

		container := testcontainers.GenericContainerRequest{
			Started:          true,
			ContainerRequest: req,
		}

		containers = append(containers, container)

	}
	ctx := context.Background()
	nodes, err := testcontainers.ParallelContainers(ctx, containers, testcontainers.ParallelContainersOptions{})
	if err != nil {
		return err
	}

	for _, node := range nodes {
		cfg, err := node.Inspect(ctx)
		if err != nil {
			return err
		}

		name := strings.Replace(cfg.Name, "/", "", 1)
		tomlString, _ := marshalCoreToml(toml)

		externalPort, err := node.MappedPort(ctx, nat.Port(coreConfig.Ports[0]))
		if err != nil {
			return err
		}

		d.lggr.Info().Msgf("%s container running with local exposed port %d", name, externalPort.Int())
		d.Core = append(d.Core, &CoreClient{
			Name: name,
			Client: &TestContainer{
				Container: node,
			},
			Config:       coreConfig,
			Toml:         tomlString,
			ExternalPort: externalPort.Int(),
		})
	}

	sort.Slice(d.Core, func(i, j int) bool {
		return d.Core[i].Name < d.Core[j].Name
	})

	return nil
}

func (d *Deployer) CreateNodesList() error {
	var nodeURLs []string

	lf, err := os.OpenFile(d.Keystone.NodesList, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}

	defer lf.Close()

	for _, coreClient := range d.Core {
		url := fmt.Sprintf("localhost:%d %s:6688 %s %s", coreClient.ExternalPort, coreClient.Name, coreClient.Config.Email, coreClient.Config.Password)
		nodeURLs = append(nodeURLs, url)
	}

	output := strings.Join(nodeURLs, "\n")
	_, err = lf.WriteString(output)
	if err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) StartContainer(containerRequest testcontainers.ContainerRequest, lggr *zerolog.Logger) (testcontainers.Container, error) {
	ctx := context.Background()

	containerRequest.LogConsumerCfg = &testcontainers.LogConsumerConfig{
		Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(10 * time.Second)},
		Consumers: []testcontainers.LogConsumer{d.containerLggr},
	}

	containerRequest.SkipReaper = true

	lggr.Info().Msgf("Starting container: %s and exposing %v ports", containerRequest.Image, containerRequest.ExposedPorts)
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: containerRequest,
		Started:          true,
		Reuse:            true,
	})
	if err != nil {
		lggr.Error().Msgf("Failed to start %s while waiting for %s - %v", containerRequest.Image, containerRequest.WaitingFor, err)
		if container != nil {
			logs, logsErr := container.Logs(ctx)
			if logsErr != nil {
				lggr.Error().Msgf("Failed to fetch logs for container %s - %v", containerRequest.Image, logsErr)
			} else {
				logContent, readErr := io.ReadAll(logs)
				if readErr != nil {
					lggr.Error().Msgf("Failed to read logs for container %s - %v", containerRequest.Image, readErr)
				} else {
					lggr.Error().Msgf("Container logs:\n%s", string(logContent))
				}
			}
		}
		return nil, err
	}
	return container, nil
}

func (d *Deployer) loadCoreToml() (*CoreConfigToml, error) {

	d.lggr.Info().Msg("Trying to load in core toml config")
	tomlFiles, err := filepath.Glob(filepath.Join(scripts.Templates, "core.toml"))
	if err != nil {
		return nil, err
	}

	if len(tomlFiles) == 0 {
		return nil, fmt.Errorf("no TOML files found in the directory")
	}

	d.lggr.Info().Msgf("Found %d toml configs, loading first match %s", len(tomlFiles), tomlFiles[0])
	var config CoreConfigToml
	if _, err := toml.DecodeFile(tomlFiles[0], &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (d *Deployer) SaveWorkflowToml(dataFeedsAddress string, workflowOwner string) error {
	toml := common.GenerateWorkflowToml(dataFeedsAddress, workflowOwner)

	filePath := fmt.Sprintf("%s/%s", d.Configs.TestFolder, "workflow.toml")

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(toml)
	if err != nil {
		return err
	}

	d.Configs.KeystoneWorkflow = filePath

	return nil
}

func marshalCoreToml(config *CoreConfigToml) (string, error) {
	var buffer bytes.Buffer
	encoder := toml.NewEncoder(&buffer)
	if err := encoder.Encode(config); err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func createNetwork() (string, error) {
	ctx := context.Background()

	net, err := network.New(ctx,
		network.WithAttachable(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create network: %w", err)
	}

	return net.Name, nil
}

func (d *Deployer) Cleanup() {

	if d.Postgres != nil {
		err := d.SaveContainerLogs(d.Postgres.Client)
		if err != nil {
			d.lggr.Error().Msgf("Error saving Postgres container logs: %v", err)
		}
		if err = d.Postgres.Client.Container.Terminate(context.Background()); err != nil {
			d.lggr.Error().Msgf("Error terminating Postgres container: %v", err)
		}
	}
	if d.Geth != nil {
		err := d.SaveContainerLogs(d.Geth.Client)
		if err != nil {
			d.lggr.Error().Msgf("Error saving Geth container logs: %v", err)
		}

		if err := d.Geth.Client.Container.Terminate(context.Background()); err != nil {
			d.lggr.Error().Msgf("Error terminating Geth container: %v", err)
		}
	}
	if d.Devnet != nil {
		err := d.SaveContainerLogs(d.Devnet.Client)
		if err != nil {
			d.lggr.Error().Msgf("Error saving Devnet container logs: %v", err)
		}

		if err := d.Devnet.Client.Container.Terminate(context.Background()); err != nil {
			d.lggr.Error().Msgf("Error terminating Devnet container: %v", err)
		}
	}

	if len(d.Core) >= 0 {
		for i := 0; i < len(d.Core); i++ {
			err := d.SaveContainerLogs(d.Core[i].Client)
			if err != nil {
				d.lggr.Error().Msgf("Error saving Core container logs: %v", err)
			}

			if err := d.Core[i].Client.Container.Terminate(context.Background()); err != nil {
				d.lggr.Error().Msgf("Error terminating Core container: %v", err)
			}
		}
	}
}

func (d *Deployer) SaveContainerLogs(container *TestContainer) error {
	ctx := context.Background()
	cDetails, err := container.Container.Inspect(ctx)
	if err != nil {
		return err
	}
	logName := fmt.Sprintf("%s-%s.log", cDetails.Name, scripts.GetRandomName(10))
	logs, err := container.Container.Logs(ctx)

	if err != nil {
		return err
	}

	bl, err := io.ReadAll(logs)
	if err != nil {
		return err
	}

	err = os.WriteFile(fmt.Sprintf("%s/%s", scripts.Logs, logName), bl, 0644)

	if err != nil {
		return err
	}

	d.lggr.Info().Msgf("Saved chainlink logs for %s as %s", cDetails.Name, logName)

	return nil
}

func (d *Deployer) FundGeth() error {

	cmdStr := []string{
		"geth",
		"attach",
		"--exec",
		fmt.Sprintf(
			"eth.sendTransaction({from: eth.accounts[0], to: \"%s\", value: 20000000000000000000000})",
			GETH_ACC_ADDRESS,
		),
		fmt.Sprintf("http://127.0.0.1:%s", d.Geth.Config.Ports[1]),
	}

	_, err := ExecCmd(d.Geth.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func ExecCmd(container *TestContainer, cmd []string, lggr zerolog.Logger) (string, error) {
	ctx := context.Background()
	sc, resp, err := container.Container.Exec(ctx, cmd)

	if err != nil {
		return "", err
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp)
	if err != nil {
		return "", err
	}

	lggr.Info().Msgf("Executing command: %s", cmd)

	if sc != 0 {
		lggr.Error().Msg(buf.String())
		return "", errors.New(fmt.Sprintf("Command returned non 0 status code, got %d", sc))
	}

	lggr.Info().Msg(buf.String())

	return buf.String(), nil
}

func (d *Deployer) PrintUrls() {

	d.lggr.Info().Msg("Printing node access details")
	d.lggr.Info().Msgf("Geth WS RPC: ws://localhost:%d", d.Geth.ExternalWSPort)
	d.lggr.Info().Msgf("Geth HTTP RPC: http://localhost:%d", d.Geth.ExternalHttpPort)

	d.lggr.Info().Msgf("Aptos Faucet RPC: %s ", d.Devnet.Config.FaucetRPC)
	d.lggr.Info().Msgf("Aptos HTTP RPC: http://localhost:%d", d.Devnet.ExternalHttpPort)
	d.lggr.Info().Msgf("Cache folder: %s", d.Keystone.ArtefactsDir)

	for i := 0; i < len(d.Core); i++ {
		d.lggr.Info().Msgf("Core node %s HTTP RPC: http://localhost:%d", d.Core[i].Name, d.Core[i].ExternalPort)
	}
}
