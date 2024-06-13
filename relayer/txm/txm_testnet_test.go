//go:build integration && testnet

package txm

import (
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/testutils"
)

func TestTxmDevnet(t *testing.T) {
	runTestnetTest(t, "https://api.devnet.aptoslabs.com")
}

func TestTxmTestnet(t *testing.T) {
	runTestnetTest(t, "https://api.testnet.aptoslabs.com")
}

func runTestnetTest(t *testing.T, rpcUrl string) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	keystore := testutils.NewTestKeystore(t, accountAddress, privateKey)

	config := AptosTxmConfig{
		RPCUrl:            rpcUrl,
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	}

	runTxmTest(t, logger, config, keystore, accountAddress, publicKey, 5)
}
