// //go:build integration && testnet

package chainreader

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/sqltest"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"

	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
)

func TestChainReaderDevnet(t *testing.T) {
	runTestnetTest(t, testutils.DevnetUrl)
}

func TestChainReaderTestnet(t *testing.T) {
	runTestnetTest(t, testutils.TestnetUrl)
}

func runTestnetTest(t *testing.T, rpcUrl string) {
	// logger := logger.Test(t)

	// privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	// if privateKey == nil {
	// 	t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	// }

	// t.Run("GetLatestValue", func(t *testing.T) {
	// 	runGetLatestValueTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	// })

	// t.Run("QueryKey", func(t *testing.T) {
	// 	runQueryKeyTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	// })
}

func TestChainreaderTemp(t *testing.T) {
	logger := logger.Test(t)

	rpcUrl := "https://fullnode.testnet.aptoslabs.com/v1"
	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	rateLimitedClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	config := crconfig.ChainReaderConfig{
		Modules: map[string]*crconfig.ChainReaderModule{
			"OffRamp": {
				Name: "offramp",
				Events: map[string]*crconfig.ChainReaderEvent{
					"ExecutionStateChanged": {
						EventHandleStructName: "OffRampState",
						EventHandleFieldName:  "execution_state_changed_events",
						EventAccountAddress:   "offramp::get_state_address",
						EventFieldRenames: map[string]crconfig.RenamedField{
							"source_chain_selector": {
								NewName: "SourceChainSelector",
							},
							"sequence_number": {
								NewName: "SequenceNumber",
							},
							"message_id": {
								NewName: "MessageId",
							},
							"message_hash": {
								NewName: "MessageHash",
							},
							"state": {
								NewName: "State",
							},
						},
					},
					"OCRConfigSet": {
						EventHandleStructName: "OffRampState",
						EventHandleFieldName:  "ocr3_base_state.config_set_events",
						EventAccountAddress:   "offramp::get_state_address",
						EventFieldRenames: map[string]crconfig.RenamedField{
							"ocr_plugin_type": {
								NewName: "OcrPluginType",
							},
							"config_digest": {
								NewName: "ConfigDigest",
							},
							"signers": {
								NewName: "Signers",
							},
							"transmitters": {
								NewName: "Transmitters",
							},
							"big_f": {
								NewName: "BigF",
							},
						},
					},
					"SourceChainConfigSet": {
						EventHandleStructName: "OffRampState",
						EventHandleFieldName:  "source_chain_config_set_events",
						EventAccountAddress:   "offramp::get_state_address",
						EventFieldRenames: map[string]crconfig.RenamedField{
							"source_chain_selector": {
								NewName: "SourceChainSelector",
							},
							"source_chain_config": {
								NewName: "SourceChainConfig",
								SubFieldRenames: map[string]crconfig.RenamedField{
									"router":                       {NewName: "Router"},
									"is_enabled":                   {NewName: "IsEnabled"},
									"min_seq_nr":                   {NewName: "MinSeqNr"},
									"is_rmn_verification_disabled": {NewName: "IsRMNVerificationDisabled"},
									"on_ramp":                      {NewName: "OnRamp"},
								},
							},
						},
					},
				},
			},
		},
		EventSyncInterval: 3 * time.Second,
		EventSyncTimeout:  2 * time.Second,
		TxSyncInterval:    5 * time.Second,
		TxSyncTimeout:     4 * time.Second,
	}

	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("Skipping testnet test as TEST_DB_URL is not set")
	}
	db := sqltest.NewDB(t, dsn)

	chainReader := NewChainReader(logger, rateLimitedClient, config, db)
	testnetAddress := "0x1dd8925f10ca7b828b86a7b6bc8509ad02867577cc90f49033dcd6594bba1576"

	binding := commontypes.BoundContract{
		Name:    "OffRamp",
		Address: testnetAddress,
	}

	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = chainReader.Start(ctx)
	require.NoError(t, err)
	defer chainReader.Close()

	logger.Infow("ChainReader started, will run for 1 minute to observe event and tx polling logs")

	time.Sleep(2 * time.Minute)

	logger.Infow("Sleep time elapsed, stopping ChainReader")

	err = chainReader.Close()
	require.NoError(t, err)

	logger.Infow("ChainReader stopped successfully")
}
