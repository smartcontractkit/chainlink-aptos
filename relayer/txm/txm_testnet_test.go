//go:build integration && testnet

package txm

import (
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
)

func TestTxmDevnet(t *testing.T) {
	runTestnetTest(t, testutils.DevnetUrl)
}

func TestTxmTestnet(t *testing.T) {
	runTestnetTest(t, testutils.TestnetUrl)
}

func runTestnetTest(t *testing.T, rpcUrl string) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	config := DefaultConfigSet

	runTxmTest(t, logger, config, rpcUrl, keystore, accountAddress, publicKey, 5)
}
