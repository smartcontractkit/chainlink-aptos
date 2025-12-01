package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deploy"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/moby/term"
	"github.com/rs/zerolog"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [command] [subcommand] --flags")
		fmt.Println("Commands: deploy, build")
		fmt.Println("Subcommands for deploy: services, contracts")
		os.Exit(1)
	}

	cmd := os.Args[1]

	commonFlags := flag.NewFlagSet("common", flag.ExitOnError)

	switch cmd {
	case "deploy":
		if len(os.Args) < 3 {
			fmt.Println("Usage: go run main.go deploy [subcommand] --flags")
			fmt.Println("Subcommands: services, contracts")
			os.Exit(1)
		}

		subCmd := os.Args[2]

		switch subCmd {
		case "services":
			err := commonFlags.Parse(os.Args[3:])
			if err != nil {
				commonFlags.Usage()
				os.Exit(1)
			}
			err = scripts.LoadEnv()
			if err != nil {
				log.Fatalf("Could not load .env file: %v", err)
			}
			deployServices()

		case "contracts":
			contractsFlags := flag.NewFlagSet("contracts", flag.ExitOnError)
			cacheFolder := contractsFlags.String("cacheFolder", "", "The test folder containing the nodelists and other test artifacts")
			gethRpc := contractsFlags.String("gethRpc", "", "Local geth http RPC url")
			chainId := contractsFlags.String("chainId", "", "Geth chain ID")
			privKey := contractsFlags.String("gethPrivKey", "", "Private key foe geth")

			err := contractsFlags.Parse(os.Args[3:])
			if err != nil {
				contractsFlags.Usage()
				os.Exit(1)
			}

			if *cacheFolder == "" || *gethRpc == "" || *chainId == "" || *privKey == "" {
				contractsFlags.Usage()
				os.Exit(1)
			}

			// checkCacheFolder(*cacheFolder)

			err = scripts.LoadEnv()
			if err != nil {
				log.Fatalf("Could not load .env file: %v", err)
			}

			DeployContracts(*cacheFolder, *gethRpc, *chainId, *privKey)

		case "jobspecs":
			jobsFlags := flag.NewFlagSet("jobspecs", flag.ExitOnError)
			cacheFolder := jobsFlags.String("cacheFolder", "", "The test folder containing the nodelists and other test artifacts")
			gethRpc := jobsFlags.String("gethRpc", "", "Local geth http RPC url")
			chainId := jobsFlags.String("chainId", "", "Geth chain ID")
			privKey := jobsFlags.String("gethPrivKey", "", "Private key for geth")

			err := jobsFlags.Parse(os.Args[3:])
			if err != nil {
				jobsFlags.Usage()
				os.Exit(1)
			}

			if *cacheFolder == "" || *gethRpc == "" || *chainId == "" {
				jobsFlags.Usage()
				os.Exit(1)
			}

			checkCacheFolder(*cacheFolder)

			err = scripts.LoadEnv()
			if err != nil {
				log.Fatalf("Could not load .env file: %v", err)
			}

			DeployJobSpecs(*cacheFolder, *gethRpc, *chainId, *privKey)

		case "workflows":
			workflowsFlags := flag.NewFlagSet("workflows", flag.ExitOnError)
			cacheFolder := workflowsFlags.String("cacheFolder", "", "The test folder containing the nodelists and other test artifacts")
			gethRpc := workflowsFlags.String("gethRpc", "", "Local geth http RPC url")
			chainId := workflowsFlags.String("chainId", "", "Geth chain ID")
			workflowFile := workflowsFlags.String("workflowFile", "", "Location of workflow")

			err := workflowsFlags.Parse(os.Args[3:])
			if err != nil {
				workflowsFlags.Usage()
				os.Exit(1)
			}

			if *cacheFolder == "" || *gethRpc == "" || *chainId == "" {
				workflowsFlags.Usage()
				os.Exit(1)
			}

			checkCacheFolder(*cacheFolder)

			err = scripts.LoadEnv()
			if err != nil {
				log.Fatalf("Could not load .env file: %v", err)
			}

			DeployWorkflows(*workflowFile, *cacheFolder, *gethRpc, *chainId)

		default:
			fmt.Printf("Invalid subcommand for deploy: %s. Use 'services' or 'contracts or jobspecs or workflows'.\n", subCmd)
			os.Exit(1)
		}

	case "build":
		buildFlags := flag.NewFlagSet("build", flag.ExitOnError)
		dir := buildFlags.String("dir", "", "Location of the directory for the build command. If not provided, the repo will be cloned.")

		err := buildFlags.Parse(os.Args[2:])
		if err != nil {
			buildFlags.Usage()
			os.Exit(1)
		}
		err = scripts.LoadEnv()
		if err != nil {
			log.Fatalf("Could not load .env file: %v", err)
		}
		buildImages(*dir)

	default:
		log.Fatalf("Invalid command: %s. Use 'deploy' or 'build'.", cmd)
	}
}

func deployServices() {

	clWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	lggr := zerolog.New(clWriter).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	deployer := deploy.New(&lggr)

	if err := deployer.DeployPostgres(); err != nil {
		log.Fatalf("Could not deploy Postgres: %v", err)
	}

	if err := deployer.DeployGeth(); err != nil {
		log.Fatalf("Could not deploy Geth: %v", err)
	}

	if err := deployer.FundGeth(); err != nil {
		log.Fatalf("Could not fund Geth: %v", err)
	}

	if err := deployer.DeployDevnet(); err != nil {
		log.Fatalf("Could not deploy Devnet: %v", err)
	}

	if err := deployer.DeployCore(); err != nil {
		log.Fatalf("Could not deploy Core: %v", err)
	}

	if err := deployer.CreateNodesList(); err != nil {
		log.Fatalf("Could not create node list: %v", err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		lggr.Info().Msgf("Received signal: %v. Shutting down.", sig)
		deployer.Cleanup()
		os.Exit(0)
	}()

	deployer.PrintUrls()
	lggr.Info().Msg("Deployment complete. Press Ctrl+C to exit.")

	select {}
}

func DeployContracts(cacheFolder string, gethHttpRpc string, chainId string, gethPrivKey string) {
	kc := deploy.Keystone{
		NodesList:    fmt.Sprintf("%s/NodesList.txt", cacheFolder),
		ArtefactsDir: cacheFolder,
		GethHttpRPC:  gethHttpRpc,
		ChainId:      chainId,
	}

	kc.DeployOCR3Contracts(gethPrivKey)
}

func DeployJobSpecs(cacheFolder string, gethHttpRpc string, chainId string, gethPrivKey string) {
	kc := deploy.Keystone{
		NodesList:    fmt.Sprintf("%s/NodesList.txt", cacheFolder),
		ArtefactsDir: cacheFolder,
		GethHttpRPC:  gethHttpRpc,
		ChainId:      chainId,
		P2PPort:      6690,
	}

	kc.DeployOCR3JobSpecs(gethPrivKey)
}

func DeployWorkflows(workflowFile string, cacheFolder string, gethHttpRpc string, chainId string) {
	kc := deploy.Keystone{
		NodesList:    fmt.Sprintf("%s/NodesList.txt", cacheFolder),
		ArtefactsDir: cacheFolder,
		GethHttpRPC:  gethHttpRpc,
		ChainId:      chainId,
	}

	kc.DeployWorkflows(workflowFile)
}

func buildImages(dir string) {
	clWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	lggr := zerolog.New(clWriter).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	checkBuildConfig()
	coreRepo := os.Getenv("CORE_REPO")
	coreSha := os.Getenv("CORE_REF")

	containerVersion := fmt.Sprintf("core-aptos-%s", coreSha)

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Fatalf("Could not create Docker client: %v", err)
	}
	defer cli.Close()

	chainlinkDir := fmt.Sprintf("%s/chainlink", scripts.Cache)
	if dir != "" {
		chainlinkDir = dir
	}

	if _, err := os.Stat(chainlinkDir); os.IsNotExist(err) {
		lggr.Info().Msgf("Cloning core repository at commit: %s", coreSha)
		if err := exec.Command("git", "clone", coreRepo, chainlinkDir).Run(); err != nil {
			log.Fatalf("Failed to clone repository: %v", err)
		}
	}

	if err := os.Chdir(chainlinkDir); err != nil {
		log.Fatalf("Failed to change directory: %v", err)
	}

	lggr.Info().Msgf("Checking out commit: %s", coreSha)
	if err := exec.Command("git", "checkout", coreSha).Run(); err != nil {
		log.Fatalf("Failed to checkout branch: %v", err)
	}

	lggr.Info().Msg("Building Docker image for Chainlink...")
	chainlinkImage := fmt.Sprintf("chainlink:%s", containerVersion)
	if err := buildDockerImage(cli, chainlinkDir, "plugins/chainlink.Dockerfile", chainlinkImage, map[string]*string{"COMMIT_SHA": &coreSha}); err != nil {
		log.Fatalf("Docker build failed for Chainlink: %v", err)
	}
	lggr.Info().Msg("Docker build successful for Chainlink.")

	lggr.Info().Msg("Building Docker image for Chainlink-Aptos...")
	aptosImage := "chainlink-aptos"
	coreImage := fmt.Sprintf("chainlink:%s", containerVersion)
	if err := buildDockerImage(cli, scripts.ProjectRoot, "scripts/chainlink.Dockerfile", aptosImage, map[string]*string{
		"BASE_IMAGE": &coreImage,
	}); err != nil {
		log.Fatalf("Docker build failed for Chainlink-Aptos: %v", err)
	}
	lggr.Info().Msg("Docker build successful for chainlink-aptos.")
}

func buildDockerImage(cli *client.Client, contextDir, dockerfilePath, imageName string, buildArgs map[string]*string) error {
	buildContext, err := archive.TarWithOptions(contextDir, &archive.TarOptions{})
	if err != nil {
		return fmt.Errorf("failed to create build context: %w", err)
	}

	options := types.ImageBuildOptions{
		Dockerfile: dockerfilePath,
		Tags:       []string{imageName},
		Remove:     true,
		BuildArgs:  buildArgs,
	}

	response, err := cli.ImageBuild(context.Background(), buildContext, options)
	if err != nil {
		return fmt.Errorf("failed to build Docker image: %w", err)
	}
	defer response.Body.Close()

	termFd, isTerm := term.GetFdInfo(os.Stdout)
	err = jsonmessage.DisplayJSONMessagesStream(response.Body, os.Stdout, termFd, isTerm, nil)
	if err != nil {
		return fmt.Errorf("failed to display docker log stream: %w", err)
	}

	return nil
}

func checkBuildConfig() {
	var errs []string
	_, ok := os.LookupEnv("CORE_REPO")
	if !ok {
		errs = append(errs, "CORE_REPO is required")
	}
	_, ok = os.LookupEnv("CORE_REF")
	if !ok {
		errs = append(errs, "CORE_REF is required")
	}
}

func checkCacheFolder(cacheFolder string) {
	if _, err := os.Stat(cacheFolder); err != nil {
		if os.IsNotExist(err) {
			panic("Cache folder does not exist")
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s/NodesList.txt", cacheFolder)); err != nil {
		if os.IsNotExist(err) {
			panic("Node list not present in cache folder")
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s/pubnodekeys.json", cacheFolder)); err != nil {
		if os.IsNotExist(err) {
			panic("Public keys not present in cache folder")
		}
	}
}
