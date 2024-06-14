//go:build integration && testnet

package chainwriter

import (
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/testutils"
)

func TestChainWriterDevnet(t *testing.T) {
	runTestnetTest(t, "https://api.devnet.aptoslabs.com")
}

func TestChainWriterTestnet(t *testing.T) {
	runTestnetTest(t, "https://api.testnet.aptoslabs.com")
}

func runTestnetTest(t *testing.T, rpcUrl string) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	runChainWriterTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey, 3)
}
