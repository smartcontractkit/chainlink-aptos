package smoke_test

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deploy"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestOCR3Keystone(t *testing.T) {
	workflowOwner := "0x00000000000000000000000000000000000000aa"

	err := scripts.LoadEnv()
	require.NoError(t, err, "Could not load .env file")
	clWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	lggr := zerolog.New(clWriter).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	deployer := deploy.New(&lggr)

	t.Cleanup(func() {
		deployer.Cleanup()
	})

	err = deployer.DeployPostgres()
	require.NoError(t, err, "Could not deploy Postgres")

	err = deployer.DeployGeth()
	require.NoError(t, err, "Could not deploy Geth")

	err = deployer.FundGeth()
	require.NoError(t, err, "Could not fund geth")

	err = deployer.DeployDevnet()
	require.NoError(t, err, "Could not deploy Devnet")

	err = deployer.DeployPlatform()
	require.NoError(t, err, "Could not deploy Platform")

	err = deployer.DeployPlatformSecondary()
	require.NoError(t, err, "Could not deploy Platform Secondary")

	err = deployer.DeployDataFeeds(deployer.Contracts.KeystoneAddress, deployer.Contracts.KeystoneSecondaryAddress)
	require.NoError(t, err, "Could not deploy Data Feeds")

	err = deployer.SetWorkflowConfigs(deployer.Contracts.DataFeedsAddress, workflowOwner)
	require.NoError(t, err, "Could not set feed configs")
	err = deployer.SetFeeds(deployer.Contracts.DataFeedsAddress)
	require.NoError(t, err, "Could not set feeds")

	err = deployer.DeployCore()
	require.NoError(t, err, "Could not deploy Core")

	err = deployer.CreateNodesList()
	require.NoError(t, err, "Could not create node list")

	lggr.Info().Msg("Deploying OCR3 contracts")
	deployer.Keystone.DeployOCR3Contracts(deploy.GETH_ACC_KEY)

	lggr.Info().Msg("Fetching node keys")
	nodeKeys, err := deployer.Keystone.FetchNodeKeys()
	require.NoError(t, err, "Could not fetch node keys")

	var pubKeys []string
	var accounts []string
	// Fund Nodes
	for _, key := range nodeKeys {
		err = deployer.FundDevnet(key.AptosAccount)
		require.NoError(t, err, "Could not fund aptos account")
		pubKeys = append(pubKeys, fmt.Sprintf("\"%s\"", key.AptosOnchainPublicKey))
		accounts = append(accounts, key.AptosAccount)
	}

	err = deployer.SetForwarderConfig(deployer.Contracts.KeystoneAddress, pubKeys)
	require.NoError(t, err, "Could not set ocr configs")

	err = deployer.SaveWorkflowToml(deployer.Contracts.DataFeedsAddress, workflowOwner)
	require.NoError(t, err, "Could not create workflow toml")

	lggr.Info().Msg("Deploying OCR3 job specs")
	deployer.Keystone.DeployOCR3JobSpecs(deploy.GETH_ACC_KEY)

	lggr.Info().Msg("Deploying workflows")
	deployer.Keystone.DeployWorkflows(deployer.Configs.KeystoneWorkflow)

	lggr.Info().Msg("Waiting for OCR3 jobs to complete")
	maxRuntime := time.Duration(10)
	maxRuntimeMinutes := maxRuntime * time.Minute
	prevBenchmark := 0
	successfulTransactionThreshold := 2
	timer := time.NewTimer(maxRuntimeMinutes)
	successfulTransactions := []string{}
	defer timer.Stop()
loop:
	for {
		select {
		case <-timer.C:
			panic(fmt.Sprintf("Max runtime of %d minutes reached, exiting loop.", maxRuntime))
		default:
			if len(successfulTransactions) >= successfulTransactionThreshold {
				break loop
			}
			var allHashes []string
			var mu sync.Mutex
			var wg sync.WaitGroup

			for _, account := range accounts {
				wg.Add(1)
				go func(account string) {
					defer wg.Done()
					hashes, err := deployer.GetAccountTransactions(account)
					require.NoError(t, err, fmt.Sprintf("Could not get account transactions for account %s", account))

					mu.Lock()
					allHashes = append(allHashes, hashes...)
					mu.Unlock()
				}(account)
			}

			wg.Wait()

			if len(allHashes) > 0 {
				for _, hash := range allHashes {
					transaction, err := deployer.GetTransactionDetailsByHash(hash)
					require.NoError(t, err, "Could not get transaction")
					if transaction.Success {
						if !slices.Contains(successfulTransactions, transaction.Hash) {
							var currBenchmark int
							lggr.Info().Msgf("Found unique successful transaction: %s", transaction.Hash)
							for _, event := range transaction.Events {
								if strings.Contains(event.Type, "FeedUpdated") {
									// Regardless of feed count the mock trigger increases per round and not per feed so we track one value
									currBenchmark, err = strconv.Atoi(event.Data.Benchmark)
									require.NoError(t, err, fmt.Sprintf("Could not parse benchmark answer, got: %s", event.Data.Benchmark))
									lggr.Info().Msgf("Found FeedUpdated event with feedId: %s and value: %d", event.Data.FeedId, currBenchmark)
									require.Greater(t, currBenchmark, prevBenchmark)
								}
							}
							prevBenchmark = currBenchmark
							successfulTransactions = append(successfulTransactions, transaction.Hash)
						}
					}
				}
			}
			lggr.Info().Msgf("Found %d successful transactions, required %d", len(successfulTransactions), successfulTransactionThreshold)
			time.Sleep(time.Second * 5)
		}
	}
}
