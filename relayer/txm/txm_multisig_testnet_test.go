//go:build integration && testnet

package txm

import (
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
)

func TestMultisigDevnet(t *testing.T) {
	runMultisigTestnetTest(t, testutils.DevnetUrl)
}

func TestMultisigTestnet(t *testing.T) {
	runMultisigTestnetTest(t, testutils.TestnetUrl)
}

func runMultisigTestnetTest(t *testing.T, rpcUrl string) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		t.Fatal("PRIVATE_KEY or ADDRESS environment variable is not set")
	}

	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	account := Account{
		privateKey:     privateKey,
		publicKey:      publicKey,
		accountAddress: accountAddress,
	}

	runMultisigTest(t, logger, rpcUrl, keystore, []Account{account}, true)
}
