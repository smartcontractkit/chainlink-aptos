//go:build integration

package txm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/testutils"
)

func TestTxmLocal(t *testing.T) {
	logger := logger.Test(t)

	privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
	if privateKey == nil {
		newPublicKey, newPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		privateKey = newPrivateKey
		publicKey = newPublicKey

		authKey := sha3.Sum256(append([]byte(publicKey), 0x00))
		accountAddress = aptos.AccountAddress(authKey)

		logger.Debugw("Created account", "publicKey", hex.EncodeToString([]byte(publicKey)), "accountAddress", accountAddress.String())
	}

	err := testutils.StartAptosNode()
	require.NoError(t, err)
	logger.Debugw("Started Aptos node")

	rpcUrl := "http://localhost:8080/v1"
	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	faucetUrl := "http://localhost:8081"
	err = testutils.FundWithFaucet(logger, client, accountAddress, faucetUrl)
	require.NoError(t, err)

	keystore := testutils.NewTestKeystore(t, accountAddress.String(), privateKey)

	config := AptosTxmConfig{
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	}

	runTxmTest(t, logger, config, rpcUrl, keystore, accountAddress, publicKey, 10)
}

func runTxmTest(t *testing.T, logger logger.Logger, config AptosTxmConfig, rpcURL string, keystore loop.Keystore, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, iterations int) {
	client, err := aptos.NewNodeClient(rpcURL, 0) // TODO: chainId
	require.NoError(t, err)
	getClient := func() (*aptos.NodeClient, error) { return client, nil }
	txm, err := New(logger, keystore, config, getClient)
	require.NoError(t, err)
	err = txm.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))
	deployTestContract(t, txm, accountAddress.String(), publicKeyHex)

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	logger.Debugw("Deployed test contract")

	// Get the current version so that we can find the transactions quickly after incrementing.

	expectedValue := 0
	for i := 0; i < iterations; i++ {
		err := txm.Enqueue(
			uuid.New().String(),
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment",
			[]string{},
			[]string{"address"},
			[]any{accountAddress})
		require.NoError(t, err)
		expectedValue += 1

		err = txm.Enqueue(
			uuid.New().String(),
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment_mult",
			[]string{},
			[]string{"address", "u64", "u64"},
			[]any{accountAddress, uint64(3), uint64(4)})
		require.NoError(t, err)
		expectedValue += 3 * 4
	}

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	resource, err := client.AccountResource(accountAddress, accountAddress.String()+"::counter::Counter")
	require.NoError(t, err)

	data, ok := resource["data"]
	require.True(t, ok)

	dataMap, ok := data.(map[string]any)
	require.True(t, ok)

	value, ok := dataMap["value"]
	require.True(t, ok)

	valueStr, ok := value.(string)
	require.True(t, ok)

	logger.Debugw("Read counter value", "value", valueStr)

	require.Equal(t, fmt.Sprintf("%d", expectedValue), valueStr)
}

func deployTestContract(t *testing.T, txm *AptosTxm, fromAddress, publicKeyHex string) {
	packageMetadataBytes, moduleBytecodeBytes := testutils.GetTestContract(t, fromAddress)

	err := txm.Enqueue(
		uuid.New().String(),
		fromAddress,
		publicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{packageMetadataBytes, [][]byte{moduleBytecodeBytes}},
	)
	require.NoError(t, err)

	// TODO: check account module to make sure it was published.

	err = txm.Enqueue(
		uuid.New().String(),
		fromAddress,
		publicKeyHex,
		fromAddress+"::counter::initialize",
		[]string{},
		[]string{},
		[]any{})
	require.NoError(t, err)

	// TODO: check account resource to make sure it was initialized.
}
