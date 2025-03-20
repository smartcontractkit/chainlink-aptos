//go:build integration && testnet

package chainwriter

import (
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
)

func TestChainWriterDevnet(t *testing.T) {
	runTestnetTest(t, testutils.DevnetUrl)
}

func TestChainWriterTestnet(t *testing.T) {
	runTestnetTest(t, testutils.TestnetUrl)
}

func runTestnetTest(t *testing.T, rpcUrl string) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	runChainWriterTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey, 3)
}
