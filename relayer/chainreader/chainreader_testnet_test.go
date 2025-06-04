//go:build integration && testnet

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
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	t.Run("GetLatestValue", func(t *testing.T) {
		runGetLatestValueTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})

	t.Run("QueryKey", func(t *testing.T) {
		runQueryKeyTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})
}
