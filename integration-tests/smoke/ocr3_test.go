package smoke_test

import (
	"fmt"
	"integration-tests/common"
	"integration-tests/deploy"
	"integration-tests/scripts"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

	err = deployer.DeployKeystone()
	require.NoError(t, err, "Could not deploy Keystone")

	err = deployer.DeployDataFeeds(deployer.Contracts.KeystoneAddress)
	require.NoError(t, err, "Could not deploy Data Feeds")

	err = deployer.SetWorkflowConfigs(deployer.Contracts.DataFeedsAddress, workflowOwner)
	require.NoError(t, err, "Could not set feed configs")

	err = deployer.SetFeeds(deployer.Contracts.DataFeedsAddress)
	require.NoError(t, err, "Could not set feeds")

	err = deployer.DeployCore()
	require.NoError(t, err, "Could not deploy Core")

	err = deployer.CreateNodeLists()
	require.NoError(t, err, "Could not create nodes list")

	deployer.Keystone.DeployContracts(deploy.GETH_ACC_KEY)
	nodeKeys, err := common.LoadPublicKeys(deployer.Keystone.PublicKeys, lggr)

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

	deployer.Keystone.DeployJobSpecs()
	deployer.Keystone.DeployWorkflows(deployer.Configs.KeystoneWorkflow)

	maxRuntime := 10 * time.Minute
	prevBenchmark := 0
	timer := time.NewTimer(maxRuntime)
	successfullTransactions := []string{}
	defer timer.Stop()
loop:
	for {
		select {
		case <-timer.C:
			panic("Max runtime of 10 minutes reached, exiting loop.")
		default:
			if len(successfullTransactions) >= 2 {
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
						if !slices.Contains(successfullTransactions, transaction.Hash) {
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
							successfullTransactions = append(successfullTransactions, transaction.Hash)
						}
					}
				}

			}

			time.Sleep(time.Second * 5)
		}
	}
}
