//go:build integration

package txm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
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

	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	config := DefaultConfigSet

	runTxmTest(t, logger, config, rpcUrl, keystore, accountAddress, publicKey, 5)
}

func runTxmTest(t *testing.T, logger logger.Logger, config Config, rpcURL string, keystore loop.Keystore, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, iterations int) {
	client, err := aptos.NewNodeClient(rpcURL, 0) // TODO: chainId
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

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	logger.Debugw("Deployed test contract")

	// Set the initial counter value as read from the module
	expectedValue := testutils.ReadCounterValue(t, client, accountAddress)
	logger.Debugw("Counter value before test", "value", expectedValue)

	// submit all txs at once and wait for all afterwards
	// helps testing reties and failure recoveries
	var txIDs []string

	for i := 0; i < iterations; i++ {
		incrementId := uuid.New().String()
		err := txm.Enqueue(
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
		expectedValue += 1
		txIDs = append(txIDs, incrementId)

		incrementMultId := uuid.New().String()
		err = txm.Enqueue(
			incrementMultId,
			getSampleTxMetadata(),
			accountAddress.String(),
			publicKeyHex,
			accountAddress.String()+"::counter::increment_mult",
			[]string{},
			[]string{"address", "u64", "u64"},
			[]any{accountAddress, uint64(3), uint64(4)},
			true,
		)
		require.NoError(t, err)
		expectedValue += 3 * 4
		txIDs = append(txIDs, incrementMultId)
	}

	for _, txId := range txIDs {
		waitForTxmId(t, txm, txId, time.Minute*2)
	}

	counterValue := testutils.ReadCounterValue(t, client, accountAddress)
	logger.Debugw("Counter value after test", "value", counterValue)

	require.Equal(t, expectedValue, counterValue)

	// submit all txs at once and wait for all afterwards
	// helps testing reties and failure recoveries
	var txIDsCRE []string

	accountBytes, err := bcs.Serialize(&accountAddress)
	require.NoError(t, err)

	threeBytes, err := bcs.SerializeU64(3)
	require.NoError(t, err)
	fourBytes, err := bcs.SerializeU64(4)
	require.NoError(t, err)

	for i := 0; i < iterations; i++ {
		incrementId := uuid.New().String()
		_, err := txm.EnqueueWithEntryFunction(
			incrementId,
			getSampleTxMetadata(),
			publicKeyHex,
			&aptos.EntryFunction{
				Module: aptos.ModuleId{
					Address: accountAddress,
					Name:    "counter",
				},
				Function: "increment",
				ArgTypes: []aptos.TypeTag{},
				Args: [][]byte{
					accountBytes,
				},
			},
			true,
		)
		require.NoError(t, err)
		expectedValue += 1
		txIDsCRE = append(txIDsCRE, incrementId)

		incrementMultId := uuid.New().String()
		_, err = txm.EnqueueWithEntryFunction(
			incrementMultId,
			getSampleTxMetadata(),
			publicKeyHex,
			&aptos.EntryFunction{
				Module: aptos.ModuleId{
					Address: accountAddress,
					Name:    "counter",
				},
				Function: "increment_mult",
				ArgTypes: []aptos.TypeTag{},
				Args: [][]byte{
					accountBytes,
					threeBytes,
					fourBytes,
				},
			},
			true,
		)
		require.NoError(t, err)
		expectedValue += 3 * 4
		txIDsCRE = append(txIDsCRE, incrementMultId)
	}

	for _, txId := range txIDsCRE {
		waitForTxmId(t, txm, txId, time.Minute*2)
	}

	counterValueCRE := testutils.ReadCounterValue(t, client, accountAddress)
	logger.Debugw("Counter value after test", "value", counterValueCRE)

	require.Equal(t, expectedValue, counterValueCRE)

	// Test GetTransactionResult for finalized transactions
	for _, txId := range txIDsCRE {
		result, err := txm.GetTransactionResult(txId)
		require.NoError(t, err)
		require.Equal(t, commontypes.Finalized, result.Status)
		require.NotEmpty(t, result.TxHash, "TxHash should be set for finalized transaction")
	}

	// Test GetTransactionResult with invalid transaction ID
	_, err = txm.GetTransactionResult("")
	require.Error(t, err)
	require.Contains(t, err.Error(), "nil tx id")

	_, err = txm.GetTransactionResult("non-existent-tx-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such tx")
}

func deployTestModule(t *testing.T, txm *AptosTxm, fromAddress aptos.AccountAddress, publicKeyHex string) {
	compilationResult := testutils.CompileTestModule(t, fromAddress)

	err := txm.Enqueue(
		uuid.New().String(),
		getSampleTxMetadata(),
		fromAddress.String(),
		publicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{compilationResult.PackageMetadata, compilationResult.BytecodeModules},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	initializeId := uuid.New().String()
	err = txm.Enqueue(
		initializeId,
		getSampleTxMetadata(),
		fromAddress.String(),
		publicKeyHex,
		fromAddress.String()+"::counter::initialize",
		[]string{},
		[]string{},
		[]any{},
		true,
	)
	require.NoError(t, err)

	// Wait for transactions to be confirmed
	waitForTxmId(t, txm, initializeId, time.Second*15)
}

func waitForTxmId(t *testing.T, txm *AptosTxm, txId string, duration time.Duration) {
	stopTime := time.Now().Add(duration)
	for time.Now().Before(stopTime) {
		time.Sleep(time.Second * 1)
		status, err := txm.GetStatus(txId)
		require.NoError(t, err)
		if status == commontypes.Finalized {
			return
		}
	}
	t.Fatalf("Failed to wait for txmId %s", txId)
}

func getSampleTxMetadata() *commontypes.TxMeta {
	workflowID := "sample-workflow-id"
	return &commontypes.TxMeta{
		WorkflowExecutionID: &workflowID,
		GasLimit:            big.NewInt(210000),
	}
}
