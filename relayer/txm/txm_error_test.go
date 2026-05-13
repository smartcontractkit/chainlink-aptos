//go:build integration

package txm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"

	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

// This test ensures that the node returns errors as expected by the txm.
func TestTxmBroadcastErrors(t *testing.T) {
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

	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	config := DefaultConfigSet

	runErrorsTest(t, logger, config, rpcUrl, keystore, accountAddress, publicKey)
}

func runErrorsTest(t *testing.T, logger logger.Logger, config Config, rpcURL string, keystore loop.Keystore, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey) {
	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rlClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcURL, 100, 30*time.Second)
	getClient := func() (aptos.AptosRpcClient, error) {
		return rlClient, nil
	}

	txm, err := New(logger, keystore, config, getClient, chainInfo.ChainID)
	require.NoError(t, err)
	err = txm.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))

	// Check if the counter module and resource already exists. This can occur if we're running on testnet.
	// We assume that if it's deployed, it's the same version as the one we're testing.
	if !testutils.HasCounterResource(client, accountAddress) {
		logger.Debugw("Deploying counter module and initializing resource")
		deployTestModule(t, txm, accountAddress, publicKeyHex)
		// Make sure the counter resource was successfully initialized
		require.True(t, testutils.HasCounterResource(client, accountAddress))
	}

	// run a few functions to increment the sequence
	initializeTxCount := 3
	var txIDs []string
	for i := 0; i < initializeTxCount; i++ {
		incrementId := uuid.New().String()

		seed := make([]uint8, 32)
		_, err := rand.Read(seed)
		require.NoError(t, err)

		err = txm.Enqueue(
			incrementId,
			getSampleTxMetadata(),
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment",
			[]string{},
			[]string{"address"},
			[]any{accountAddress},
			true,
		)
		require.NoError(t, err)
		txIDs = append(txIDs, incrementId)
	}

	for _, txId := range txIDs {
		waitForTxmId(t, txm, txId, time.Minute*2)
	}

	// Get an AptosTx for the increment function call, since it will succeed on simulates.
	var selectedTx *AptosTx
	for _, tx := range txm.transactions {
		if tx.FunctionName != "increment" {
			continue
		}
		selectedTx = tx
		break
	}
	require.NotNil(t, selectedTx)

	sequenceNumber, err := txm.getSequenceNumber(rlClient, accountAddress)
	require.NoError(t, err)

	rawTx, err := txm.createRawTx(rlClient, selectedTx, sequenceNumber)
	require.NoError(t, err)

	rawTx.SequenceNumber = sequenceNumber - 1
	signedTx, err := txm.createSignedTx(rlClient, rawTx, selectedTx.PublicKey, selectedTx.FromAddress)
	require.NoError(t, err)

	_, err = client.SubmitTransaction(signedTx)
	require.Error(t, err)
	require.ErrorContains(t, err, "SEQUENCE_NUMBER_TOO_OLD")

	// Test with expired transaction
	rawTx.SequenceNumber = sequenceNumber
	rawTx.ExpirationTimestampSeconds = rawTx.ExpirationTimestampSeconds - *txm.config.TxExpirationSecs - 3600 // 1 hour ago
	signedTx, err = txm.createSignedTx(rlClient, rawTx, selectedTx.PublicKey, selectedTx.FromAddress)
	require.NoError(t, err)

	_, err = client.SubmitTransaction(signedTx)
	require.Error(t, err)
	require.ErrorContains(t, err, "TRANSACTION_EXPIRED")
}
