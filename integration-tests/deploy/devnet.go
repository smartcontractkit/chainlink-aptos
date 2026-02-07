package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"

	"github.com/docker/go-connections/nat"
	"github.com/go-resty/resty/v2"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func (d *Deployer) DeployDevnet() error {
	devnetConfig, err := ValidateDevnet()

	if err != nil {
		return err
	}

	absPath, err := filepath.Abs(scripts.Contracts)
	if err != nil {
		return err
	}
	req := testcontainers.ContainerRequest{
		Image:        devnetConfig.Image,
		ExposedPorts: devnetConfig.Ports,
		WaitingFor:   wait.ForLog("Faucet is ready"),
		Networks:     []string{d.Network},
		NetworkAliases: map[string][]string{
			d.Network: {devnetConfig.Name},
		},
		Name:          devnetConfig.Name,
		ImagePlatform: "linux/amd64",
		Cmd: []string{
			"aptos",
			"node",
			"run-local-testnet",
			"--with-faucet",
			"--force-restart",
			"--test-dir",
			"/testnet",
			"--bind-to",
			"0.0.0.0",
		},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      absPath,
				ContainerFilePath: "/",
			},
		},
	}

	container, err := d.StartContainer(req, d.lggr)
	if err != nil {
		return err
	}

	ctx := context.Background()
	externalFaucetPort, err := container.MappedPort(ctx, nat.Port(devnetConfig.Ports[0]))
	if err != nil {
		return err
	}

	d.lggr.Info().Msgf("%s container running with local faucet exposed port %d", devnetConfig.Name, externalFaucetPort.Int())

	externalHttpPort, err := container.MappedPort(ctx, nat.Port(devnetConfig.Ports[1]))
	if err != nil {
		return err
	}

	d.lggr.Info().Msgf("%s container running with local http exposed port %d", devnetConfig.Name, externalHttpPort.Int())

	restyClient := resty.New()
	restyClient.BaseURL = fmt.Sprintf("http://127.0.0.1:%d", externalHttpPort.Int())

	d.Devnet = &DevnetClient{
		Client:             &TestContainer{Container: container},
		Config:             devnetConfig,
		ExternalFaucetPort: externalFaucetPort.Int(),
		ExternalHttpPort:   externalHttpPort.Int(),
		RestyClient:        restyClient,
	}

	cmdStr := []string{
		"aptos",
		"init",
		"--network=local",
		"--assume-yes",
		fmt.Sprintf("--private-key=%s", DEVNET_ACC_PRIV_KEY),
	}

	_, err = ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) FundDevnet(account string) error {

	cmdStr := []string{
		"aptos",
		"account",
		"fund-with-faucet",
		"--account",
		account,
	}

	_, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) DeployPlatform() error {
	cmdStr := []string{
		"aptos",
		"move",
		"create-object-and-publish-package",
		"--package-dir=/contracts/platform",
		"--address-name=platform",
		"--named-addresses",
		fmt.Sprintf("owner=%s", DEVNET_ACC),
		"--profile=default",
		"--assume-yes",
	}

	out, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	// Fetch contract address from output
	regex := regexp.MustCompile(`0x[a-zA-Z0-9]+`)
	d.Contracts.KeystoneAddress = regex.FindString(strings.Split(out, "Code was successfully deployed to object address ")[1])

	if d.Contracts.KeystoneAddress == "" {
		return errors.New("Could not set keystone address")
	}

	d.lggr.Info().Msg(out)
	return nil
}

func (d *Deployer) DeployPlatformSecondary() error {
	cmdStr := []string{
		"aptos",
		"move",
		"create-object-and-publish-package",
		"--package-dir=/contracts/platform_secondary",
		"--address-name=platform_secondary",
		"--named-addresses",
		fmt.Sprintf("owner_secondary=%s", DEVNET_ACC),
		"--profile=default",
		"--assume-yes",
	}

	out, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	// Fetch contract address from output
	regex := regexp.MustCompile(`0x[a-zA-Z0-9]+`)
	d.Contracts.KeystoneSecondaryAddress = regex.FindString(strings.Split(out, "Code was successfully deployed to object address ")[1])

	if d.Contracts.KeystoneSecondaryAddress == "" {
		return errors.New("Could not set keystone secondary address")
	}

	d.lggr.Info().Msg(out)
	return nil
}

func (d *Deployer) DeployDataFeeds(platformAddress string, platformSecondaryAddress string) error {
	cmdStr := []string{
		"aptos",
		"move",
		"create-object-and-publish-package",
		"--package-dir=/contracts/data-feeds",
		"--address-name=data_feeds",
		"--named-addresses",
		fmt.Sprintf("platform=%s,owner=%s,platform_secondary=%s,owner_secondary=%s", platformAddress, DEVNET_ACC, platformSecondaryAddress, DEVNET_ACC),
		"--profile=default",
		"--assume-yes",
	}

	out, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	// Fetch contract address from output
	regex := regexp.MustCompile(`0x[a-zA-Z0-9]+`)
	d.Contracts.DataFeedsAddress = regex.FindString(strings.Split(out, "Code was successfully deployed to object address ")[1])

	if d.Contracts.DataFeedsAddress == "" {
		return errors.New("Could not set data feeds address")
	}

	d.lggr.Info().Msg(out)
	return nil
}

func (d *Deployer) SetWorkflowConfigs(dataFeedsAddress string, workflowOwner string) error {
	cmdStr := []string{
		"aptos",
		"move",
		"run",
		"--function-id",
		fmt.Sprintf("%s::registry::set_workflow_config", dataFeedsAddress),
		"--assume-yes",
		"--args",
		fmt.Sprintf("hex:[\"%s\"]", workflowOwner),
		"hex:[]",
	}

	_, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) SetFeeds(dataFeedsAddress string) error {
	cmdStr := []string{
		"aptos",
		"move",
		"run",
		"--function-id",
		fmt.Sprintf("%s::registry::set_feeds", dataFeedsAddress),
		"--assume-yes",
		"--args",
		"hex:[\"0x0003111111111111111100000000000000000000000000000000000000000000\"]",
		"string:[\"FOOBAR\"]",
		"hex:0x99",
	}

	_, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	cmdStr = []string{
		"aptos",
		"move",
		"run",
		"--function-id",
		fmt.Sprintf("%s::registry::set_feeds", dataFeedsAddress),
		"--assume-yes",
		"--args",
		"hex:[\"0x0003222222222222222200000000000000000000000000000000000000000000\"]",
		"string:[\"BARFOO\"]",
		"hex:0x99",
	}

	_, err = ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) SetForwarderConfig(keystoneAddress string, keys []string) error {
	cmdStr := []string{
		"aptos",
		"move",
		"run",
		"--function-id",
		fmt.Sprintf("%s::forwarder::set_config", keystoneAddress),
		"--assume-yes",
		"--args",
		"u32:1",
		"u32:1",
		"u8:1",
		fmt.Sprintf("hex:[%s]", strings.Join(keys, ",")),
	}

	_, err := ExecCmd(d.Devnet.Client, cmdStr, *d.lggr)
	if err != nil {
		return err
	}

	return nil
}

func (d *Deployer) GetAccountTransactions(account string) ([]string, error) {
	resp, err := d.Devnet.RestyClient.R().
		EnableTrace().
		Get(fmt.Sprintf("/v1/accounts/%s/transactions", account))

	if err != nil {
		return nil, err
	}

	var transactions []AccountTransaction
	err = json.Unmarshal(resp.Body(), &transactions)
	if err != nil {
		return nil, err
	}

	hashes := []string{}
	if len(transactions) > 0 {
		for _, transaction := range transactions {
			// d.lggr.Debug().Msgf("Found transaction hash: %s for address 0x%s", transaction.Hash, account)
			hashes = append(hashes, transaction.Hash)
		}
	}

	return hashes, nil
}

func (d *Deployer) GetTransactionDetailsByHash(hash string) (TransactionByHash, error) {
	resp, err := d.Devnet.RestyClient.R().
		EnableTrace().
		Get(fmt.Sprintf("/v1/transactions/by_hash/%s", hash))

	if err != nil {
		return TransactionByHash{}, err
	}

	var transaction TransactionByHash
	err = json.Unmarshal(resp.Body(), &transaction)
	if err != nil {
		return TransactionByHash{}, err
	}

	return transaction, nil
}
