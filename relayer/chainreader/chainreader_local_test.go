//go:build integration

package chainreader

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
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

func TestChainReaderLocal(t *testing.T) {
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

	runChainReaderTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
}

func runChainReaderTest(t *testing.T, logger logger.Logger, rpcUrl string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	keystore := testutils.NewTestKeystore(t, accountAddress.String(), privateKey)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)
	getClient := func() (*aptos.NodeClient, error) { return client, nil }

	txmConfig := txm.AptosTxmConfig{
		BroadcastChanSize: 100,
		ConfirmPollSecs:   2,
	}

	txmgr, err := txm.New(logger, keystore, txmConfig, getClient)
	require.NoError(t, err)

	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))

	packageMetadataBytes, moduleBytecodeBytes := testutils.GetEchoContract(t, accountAddress.String())

	err = txmgr.Enqueue(
		uuid.New().String(),
		accountAddress.String(),
		publicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{packageMetadataBytes, [][]byte{moduleBytecodeBytes}},
	)
	require.NoError(t, err)

	// publishing the package could fail if it's already deployed, eg. on testnet,
	// so we don't check beyond transactions being broadcast and confirmed.
	for {
		queueLen, unconfirmedLen := txmgr.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Functions: map[string]*ChainReaderFunction{
					"replacementNameEchoU64": {
						Name: "echo_u64",
						Params: []ChainReaderFunctionParam{
							{
								Name: "Value1",
								Type: "u64",
							},
						},
					},
					"echo_u32_u64_tuple": {
						Params: []ChainReaderFunctionParam{
							{
								Name: "Value1",
								Type: "u32",
							},
							{
								Name: "Value2",
								Type: "u64",
							},
						},
					},
					"echo_string": {
						Params: []ChainReaderFunctionParam{
							{
								Name: "Value1",
								Type: "0x1::string::String",
							},
						},
					},
					"echo_byte_vector": {
						Params: []ChainReaderFunctionParam{
							{
								Name: "Value1",
								Type: "vector<u8>",
							},
						},
					},
					"echo_byte_vector_vector": {
						Params: []ChainReaderFunctionParam{
							{
								Name: "Value1",
								Type: "vector<vector<u8>>",
							},
						},
					},
				},
			},
		},
	}

	chainReader := NewChainReader(logger, client, config)
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{{
		Name:    "testContract",
		Address: accountAddress.String(),
	}})
	require.NoError(t, err)

	confidenceLevel := primitives.Finalized

	expectedUint64 := uint64(42)
	var retUint64 uint64
	err = chainReader.GetLatestValue(context.Background(), "testContract", "replacementNameEchoU64", confidenceLevel, struct {
		Value1 uint64
	}{Value1: expectedUint64}, &retUint64)
	require.NoError(t, err)
	require.Equal(t, expectedUint64, retUint64)

	expectedTuple := []uint64{11, 22}
	var retTuple []uint64
	err = chainReader.GetLatestValue(context.Background(), "testContract", "echo_u32_u64_tuple", confidenceLevel, struct {
		Value1 uint32
		Value2 uint64
	}{Value1: uint32(expectedTuple[0]), Value2: expectedTuple[1]}, &retTuple)
	require.NoError(t, err)
	require.Equal(t, expectedTuple, retTuple)

	expectedString := "hello world"
	var retString string
	err = chainReader.GetLatestValue(context.Background(), "testContract", "echo_string", confidenceLevel, struct {
		Value1 string
	}{Value1: expectedString}, &retString)
	require.NoError(t, err)
	require.Equal(t, expectedString, retString)

	expectedSlice := []byte{42, 11, 22, 59}
	var retSlice []byte
	err = chainReader.GetLatestValue(context.Background(), "testContract", "echo_byte_vector", confidenceLevel, struct {
		Value1 []byte
	}{Value1: expectedSlice}, &retSlice)
	require.NoError(t, err)
	require.Equal(t, expectedSlice, retSlice)

	expectedSliceSlice := [][]byte{{42, 11}, {22, 59}}
	var retSliceSlice [][]byte
	err = chainReader.GetLatestValue(context.Background(), "testContract", "echo_byte_vector_vector", confidenceLevel, struct {
		Value1 [][]byte
	}{Value1: expectedSliceSlice}, &retSliceSlice)
	require.NoError(t, err)
	require.Equal(t, expectedSliceSlice, retSliceSlice)
}
