//go:build integration

package chainwriter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

func TestChainWriterLocal(t *testing.T) {
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

	runChainWriterTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey, 3)
}

func runChainWriterTest(t *testing.T, logger logger.Logger, rpcURL string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, iterations int) {
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rlClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcURL, 100, 30*time.Second)
	getClient := func() (aptos.AptosRpcClient, error) { return rlClient, nil }

	txmConfig := txm.DefaultConfigSet

	txmgr, err := txm.New(logger, keystore, txmConfig, getClient, chainInfo.ChainID)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))

	config := ChainWriterConfig{
		Modules: map[string]*ChainWriterModule{
			"code": {
				Functions: map[string]*ChainWriterFunction{
					"publish_package_txn": {
						PublicKey: publicKeyHex,
						Params: []config.AptosFunctionParam{
							{
								Name:     "PackageMetadata",
								Type:     "vector<u8>",
								Required: true,
							},
							{
								Name:     "ModuleBytecode",
								Type:     "vector<vector<u8>>",
								Required: true,
							},
						},
					},
				},
			},
			"testContract": {
				Name: "counter",
				Functions: map[string]*ChainWriterFunction{
					"counterInitialize": {
						Name:      "initialize",
						PublicKey: publicKeyHex,
					},
					"counterIncrement": {
						Name:      "increment",
						PublicKey: publicKeyHex,
						Params: []config.AptosFunctionParam{
							{
								Name:         "ResourceAddress",
								Type:         "address",
								DefaultValue: accountAddress,
							},
						},
					},
					"counterIncrementMult": {
						Name:      "increment_mult",
						PublicKey: publicKeyHex,
						Params: []config.AptosFunctionParam{
							{
								Name:         "ResourceAddress",
								Type:         "address",
								DefaultValue: accountAddress,
							},
							{
								Name:     "MultiplierA",
								Type:     "u64",
								Required: true,
							},
							{
								Name:     "MultiplierB",
								Type:     "u64",
								Required: true,
							},
						},
					},
				},
			},
		},
	}

	chainWriter := NewChainWriter(logger, rlClient, txmgr, config)

	compilationResult := testutils.CompileTestModule(t, accountAddress)

	publishId := uuid.New().String()
	publishPackageArgs := struct {
		PackageMetadata []byte
		ModuleBytecode  [][]byte
	}{
		PackageMetadata: compilationResult.PackageMetadata,
		ModuleBytecode:  compilationResult.BytecodeModules,
	}
	err = chainWriter.SubmitTransaction(
		context.Background(),
		"code",
		"publish_package_txn",
		publishPackageArgs,
		publishId,
		"0x1",
		/* meta= */ nil,
		big.NewInt(0))
	require.NoError(t, err)
	waitForTransaction(t, chainWriter, publishId, 10)

	initializeId := uuid.New().String()
	err = chainWriter.SubmitTransaction(
		context.Background(),
		"testContract",
		"counterInitialize",
		/* args= */ nil,
		initializeId,
		accountAddress.String(),
		/* meta= */ nil,
		big.NewInt(0))
	require.NoError(t, err)
	waitForTransaction(t, chainWriter, initializeId, 10)

	incrementIds := []string{}
	expectedValue := 0
	for i := 0; i < iterations; i++ {
		incrementId := uuid.New().String()
		err = chainWriter.SubmitTransaction(
			context.Background(),
			"testContract",
			"counterIncrement",
			/* args= */ nil,
			incrementId,
			accountAddress.String(),
			/* meta= */ nil,
			big.NewInt(0))
		require.NoError(t, err)
		incrementIds = append(incrementIds, incrementId)
		expectedValue++

		incrementMultId := uuid.New().String()
		incrementMultArgs := struct {
			MultiplierA uint64
			MultiplierB uint64
		}{
			MultiplierA: 3,
			MultiplierB: 4,
		}
		err = chainWriter.SubmitTransaction(
			context.Background(),
			"testContract",
			"counterIncrementMult",
			incrementMultArgs,
			incrementMultId,
			accountAddress.String(),
			/* meta= */ nil,
			big.NewInt(0))
		require.NoError(t, err)
		incrementIds = append(incrementIds, incrementMultId)
		expectedValue += 3 * 4
	}

	// TODO: this could end up waiting a long time (10 secs * number of transactions)
	for _, id := range incrementIds {
		waitForTransaction(t, chainWriter, id, 10)
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

func waitForTransaction(t *testing.T, chainWriter commontypes.ContractWriter, id string, waitSecs int) {
	for i := 1; i <= waitSecs; i++ {
		status, err := chainWriter.GetTransactionStatus(context.Background(), id)
		require.NoError(t, err)

		if status == commontypes.Pending || status == commontypes.Unconfirmed {
			time.Sleep(time.Second)
		} else if status == commontypes.Finalized {
			return
		} else {
			t.Fatalf("failed to wait for transaction %s, got status %d", id, status)
		}
	}
	t.Fatalf("timed out waiting for transaction %s", id)
}
