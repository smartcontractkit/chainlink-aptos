//go:build integration

package chainreader

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/sqltest"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/loop"
	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

func TestChainReaderLocal(t *testing.T) {
	logger := logger.Test(t)

	// Setup test environment
	privateKey, publicKey, accountAddress := setupTestAccount(t, logger)
	err := testutils.StartAptosNode()
	require.NoError(t, err)
	logger.Debugw("Started Aptos node")

	rpcUrl := "http://localhost:8080/v1"
	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	faucetUrl := "http://localhost:8081"
	err = testutils.FundWithFaucet(logger, client, accountAddress, faucetUrl)
	require.NoError(t, err)

	t.Run("GetLatestValue", func(t *testing.T) {
		runGetLatestValueTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})

	t.Run("QueryKey", func(t *testing.T) {
		runQueryKeyTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})

	t.Run("QueryKeyPersistent", func(t *testing.T) {
		runQueryKeyPersistentTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})
}

func setupTestAccount(t *testing.T, logger logger.Logger) (ed25519.PrivateKey, ed25519.PublicKey, aptos.AccountAddress) {
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
	return privateKey, publicKey, accountAddress
}

func runGetLatestValueTest(t *testing.T, logger logger.Logger, rpcUrl string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	rateLimitedClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	getClient := func() (aptos.AptosRpcClient, error) { return rateLimitedClient, nil }

	txmConfig := txm.DefaultConfigSet
	txmgr, err := txm.New(logger, keystore, txmConfig, getClient)
	require.NoError(t, err)

	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))

	compilationResult := testutils.CompileTestModule(t, accountAddress)

	txId := uuid.New().String()
	err = txmgr.Enqueue(
		txId,
		getSampleTxMetadata(),
		accountAddress.String(),
		publicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{compilationResult.PackageMetadata, compilationResult.BytecodeModules},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	confirmed := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second * 1)
		status, err := txmgr.GetStatus(txId)
		require.NoError(t, err)
		if status != commontypes.Unconfirmed {
			confirmed = true
			break
		}
	}
	require.True(t, confirmed)

	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Functions: map[string]*ChainReaderFunction{
					"echo_u64": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "u64",
							},
						},
					},
					"echo_u32_u64_tuple": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "u32",
							},
							{
								Name: "Value2",
								Type: "u64",
							},
						},
						ResultTupleToStruct: []string{"first", "second"},
					},
					"echo_string": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "0x1::string::String",
							},
						},
					},
					"echo_byte_vector": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<u8>",
							},
						},
					},
					"echo_u32_vector": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<u32>",
							},
						},
					},
					"echo_byte_vector_vector": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<vector<u8>>",
							},
						},
					},
					"echo_u256": {
						Params: []AptosFunctionParam{
							{
								Name: "Value1",
								Type: "u256",
							},
						},
					},
					"get_complex_struct": {
						Params: []AptosFunctionParam{
							{
								Name: "Val",
								Type: "u64",
							},
							{
								Name: "Text",
								Type: "0x1::string::String",
							},
						},
						ResultFieldRenames: map[string]RenamedField{
							"flag": {
								NewName: "RenamedFlag",
							},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]RenamedField{
									"id":          {NewName: "RenamedId"},
									"description": {NewName: "RenamedDescription"},
								},
							},
							"values": {
								NewName: "RenamedValues",
							},
						},
					},
					"get_complex_struct_array": {
						Params: []AptosFunctionParam{
							{
								Name: "Val",
								Type: "u64",
							},
							{
								Name: "Text",
								Type: "0x1::string::String",
							},
						},
						ResultFieldRenames: map[string]RenamedField{
							"flag": {
								NewName: "RenamedFlag",
							},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]RenamedField{
									"id":          {NewName: "RenamedId"},
									"description": {NewName: "RenamedDescription"},
								},
							},
							"values": {
								NewName: "RenamedValues",
							},
						},
					},
					"get_complex_struct_unwrapped": {
						Name: "get_complex_struct",
						Params: []AptosFunctionParam{
							{
								Name: "Val",
								Type: "u64",
							},
							{
								Name: "Text",
								Type: "0x1::string::String",
							},
						},
						ResultUnwrapStruct: []string{"nested"},
					},
				},
			},
		},
	}

	binding := commontypes.BoundContract{
		Name:    "testContract",
		Address: accountAddress.String(),
	}

	chainReader := NewChainReader(logger, rateLimitedClient, config, nil)
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	confidenceLevel := primitives.Finalized
	u256Val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee", 16)
	testString := "hello world"
	testBytes := []byte{42}
	testBytesSlice := [][]byte{{42, 11}, {22, 59}}

	t.Run("Individual reads", func(t *testing.T) {
		var retUint64 uint64
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u64", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 uint64 }{Value1: 42},
			&retUint64,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(42), retUint64)

		var retU256 *big.Int
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u256", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 *big.Int }{Value1: u256Val},
			&retU256,
		)
		require.NoError(t, err)
		require.Equal(t, u256Val, retU256)

		var retString string
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_string", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 string }{Value1: testString},
			&retString,
		)
		require.NoError(t, err)
		require.Equal(t, testString, retString)

		var retBytes []byte
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_byte_vector", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 []byte }{Value1: testBytes},
			&retBytes,
		)
		require.NoError(t, err)
		require.Equal(t, testBytes, retBytes)

		var retU32Vector []uint32
		inputVector := []uint32{99}
		err := chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u32_vector", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 []uint32 }{Value1: inputVector},
			&retU32Vector,
		)
		require.NoError(t, err)
		require.Equal(t, inputVector, retU32Vector)

		var retBytesSlice [][]byte
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_byte_vector_vector", accountAddress.String()),
			confidenceLevel,
			struct{ Value1 [][]byte }{Value1: testBytesSlice},
			&retBytesSlice,
		)
		require.NoError(t, err)
		require.Equal(t, testBytesSlice, retBytesSlice)

		var retComplexStruct ComplexStruct
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-get_complex_struct", accountAddress.String()),
			confidenceLevel,
			struct {
				Val  uint64
				Text string
			}{Val: 100, Text: "example"},
			&retComplexStruct,
		)
		require.NoError(t, err)
		require.True(t, retComplexStruct.RenamedFlag, "expected flag to be true")
		require.Equal(t, uint64(100), retComplexStruct.RenamedNested.RenamedId)
		require.Equal(t, "example", retComplexStruct.RenamedNested.RenamedDescription)
		require.Equal(t, []uint64{100, 101}, retComplexStruct.RenamedValues)

		var retComplexArray []ComplexStruct
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-get_complex_struct_array", accountAddress.String()),
			confidenceLevel,
			struct {
				Val  uint64
				Text string
			}{Val: 200, Text: "batch"},
			&retComplexArray,
		)
		require.NoError(t, err)
		require.Len(t, retComplexArray, 2)
		for _, cs := range retComplexArray {
			require.True(t, cs.RenamedFlag, "expected flag to be true")
			require.Equal(t, uint64(200), cs.RenamedNested.RenamedId)
			require.Equal(t, "batch", cs.RenamedNested.RenamedDescription)
			require.Equal(t, []uint64{200, 201}, cs.RenamedValues)
		}
	})

	t.Run("Batch reads", func(t *testing.T) {
		var retUint64 uint64
		var retU256 *big.Int
		var retString string
		var retBytes []byte
		var retBytesSlice [][]byte

		request := commontypes.BatchGetLatestValuesRequest{
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()}: {
				{
					ReadName:  "echo_u64",
					Params:    struct{ Value1 uint64 }{Value1: 42},
					ReturnVal: &retUint64,
				},
				{
					ReadName:  "echo_u256",
					Params:    struct{ Value1 *big.Int }{Value1: u256Val},
					ReturnVal: &retU256,
				},
				{
					ReadName:  "echo_string",
					Params:    struct{ Value1 string }{Value1: testString},
					ReturnVal: &retString,
				},
				{
					ReadName:  "echo_byte_vector",
					Params:    struct{ Value1 []byte }{Value1: testBytes},
					ReturnVal: &retBytes,
				},
				{
					ReadName:  "echo_byte_vector_vector",
					Params:    struct{ Value1 [][]byte }{Value1: testBytesSlice},
					ReturnVal: &retBytesSlice,
				},
			},
		}

		result, err := chainReader.BatchGetLatestValues(context.Background(), request)
		require.NoError(t, err)

		batchResults := result[commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()}]
		require.Len(t, batchResults, 5)

		require.Equal(t, uint64(42), retUint64)
		require.Equal(t, u256Val, retU256)
		require.Equal(t, testString, retString)
		require.Equal(t, testBytes, retBytes)
		require.Equal(t, testBytesSlice, retBytesSlice)
	})

	t.Run("Wrapped result read", func(t *testing.T) {
		type WrappedTuple struct {
			First  uint32 `json:"first"`
			Second uint64 `json:"second"`
		}
		var ret WrappedTuple
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u32_u64_tuple", accountAddress.String()),
			confidenceLevel,
			struct {
				Value1 uint32
				Value2 uint64
			}{Value1: 11, Value2: 22},
			&ret,
		)
		require.NoError(t, err)

		require.Equal(t, uint32(11), ret.First)
		require.Equal(t, uint64(22), ret.Second)
	})

	t.Run("Unwrapped result read", func(t *testing.T) {
		type UnwrappedNested struct {
			Id          uint64 `json:"id"`
			Description string `json:"description"`
		}
		var ret UnwrappedNested
		err = chainReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-get_complex_struct_unwrapped", accountAddress.String()),
			confidenceLevel,
			struct {
				Val  uint64
				Text string
			}{Val: 150, Text: "test"},
			&ret,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(150), ret.Id)
		require.Equal(t, "test", ret.Description)
	})
}

func emitManyEvents(t *testing.T, txmgr *txm.AptosTxm, address, publicKeyHex string, count int) {
	for i := 0; i < count; i++ {
		txId := uuid.New().String()
		err := txmgr.Enqueue(
			txId,
			getSampleTxMetadata(),
			address,
			publicKeyHex,
			fmt.Sprintf("%s::echo::echo_with_events", address),
			[]string{},
			[]string{"u64", "0x1::string::String", "vector<u8>"},
			[]any{uint64(i), fmt.Sprintf("test%d", i), []byte{byte(i)}},
			true,
		)
		require.NoError(t, err)
		waitForTx(t, txmgr, txId)
	}
}

func runQueryKeyTest(t *testing.T, logger logger.Logger, rpcUrl string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	rateLimitedClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	compilationResult := testutils.CompileTestModule(t, accountAddress)
	publicKeyHex := hex.EncodeToString([]byte(publicKey))

	txmgr := initTxManager(t, logger, keystore, rateLimitedClient)

	txId := deployContract(t, txmgr, accountAddress.String(), publicKeyHex, compilationResult)
	waitForTx(t, txmgr, txId)

	// Emit 20 events initially
	emitManyEvents(t, txmgr, accountAddress.String(), publicKeyHex, 20)

	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Events: map[string]*ChainReaderEvent{
					"SingleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "single_value_events",
						// retrieve using 2 address components
						EventAccountAddress: accountAddress.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]RenamedField{
							"value": {
								NewName: "SingleUintValue",
							},
						},
					},
					"DoubleValueEvent": {
						// don't specify event handle address to let it be filled out
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "double_value_events",
						EventAccountAddress:   accountAddress.String(),
					},
					"VectorVectorEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "vector_vector_events",
						// retrieve using 3 address components
						EventAccountAddress: "echo::get_event_address",
					},
				},
			},
		},
	}

	chainReader := NewChainReader(logger, rateLimitedClient, config, nil)
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{
		{Name: "testContract", Address: accountAddress.String()},
	})
	require.NoError(t, err)

	t.Run("Get events using timestamp filter", func(t *testing.T) {
		allSeqs, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, allSeqs)

		midIdx := len(allSeqs) / 2
		midTimestamp := allSeqs[midIdx].Head.Timestamp

		filter := query.KeyFilter{
			Key:         "SingleValueEvent",
			Expressions: []query.Expression{query.Timestamp(midTimestamp, primitives.Gte)},
		}

		filteredSeqs, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, filteredSeqs)

		for _, seq := range filteredSeqs {
			require.GreaterOrEqual(t, seq.Head.Timestamp, midTimestamp)
		}
	})

	t.Run("Complex filtering with multiple comparators", func(t *testing.T) {
		filter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(3), Operator: primitives.Gte},
					primitives.ValueComparator{Value: uint64(7), Operator: primitives.Lt},
				),
			},
		}

		sequences, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			filter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, sequences)
		for _, seq := range sequences {
			evt := seq.Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, evt.SingleUintValue, uint64(3))
			require.Less(t, evt.SingleUintValue, uint64(7))
		}

		// Test multiple independent comparators
		multiFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(2), Operator: primitives.Gte},
				),
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(8), Operator: primitives.Lt},
				),
			},
		}

		sequences, err = chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			multiFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, sequences)
		for _, seq := range sequences {
			evt := seq.Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, evt.SingleUintValue, uint64(2))
			require.Less(t, evt.SingleUintValue, uint64(8))
		}
	})

	t.Run("Error cases", func(t *testing.T) {
		// Test invalid field name
		invalidFieldFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("NonExistentField",
					primitives.ValueComparator{Value: uint64(1), Operator: primitives.Eq},
				),
			},
		}

		sequences, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			invalidFieldFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Empty(t, sequences) // Should return empty result for non-existent field

		// Test mismatched value type
		invalidTypeFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: "not a number", Operator: primitives.Eq},
				),
			},
		}

		sequences, err = chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			invalidTypeFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Empty(t, sequences) // Should return empty result for type mismatch
	})

	t.Run("Combined filtering with timestamp", func(t *testing.T) {
		allSeqs, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, allSeqs)

		midTs := allSeqs[len(allSeqs)/2].Head.Timestamp

		combinedFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Timestamp(midTs, primitives.Gte),
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(15), Operator: primitives.Lte},
				),
			},
		}

		sequences, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			combinedFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, sequences)
		for _, seq := range sequences {
			evt := seq.Data.(*SingleValueEvent)
			require.LessOrEqual(t, evt.SingleUintValue, uint64(15))
			require.GreaterOrEqual(t, seq.Head.Timestamp, midTs)
		}
	})

	t.Run("Get events sorted in desc", func(t *testing.T) {
		sequences, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{
				Limit: query.CountLimit(10),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Desc),
				},
			},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Len(t, sequences, 10)
		for i := 0; i < len(sequences)-1; i++ {
			require.Greater(t, sequences[i].Data.(*SingleValueEvent).SingleUintValue,
				sequences[i+1].Data.(*SingleValueEvent).SingleUintValue)
		}
	})

	t.Run("Handle concurrent event emission", func(t *testing.T) {
		initialCount := 20
		concurrentCount := 15

		// Start concurrent emission in background
		done := make(chan bool)
		go func() {
			emitManyEvents(t, txmgr, accountAddress.String(), publicKeyHex, concurrentCount)
			done <- true
		}()

		seenSequences := make(map[uint64]bool)
		maxAttempts := 10
		success := false
		var lastSeq uint64

		for attempt := 0; attempt < maxAttempts && !success; attempt++ {
			sequences, err := chainReader.QueryKey(
				context.Background(),
				commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
				query.KeyFilter{Key: "SingleValueEvent"},
				query.LimitAndSort{
					Limit: query.CountLimit(50),
					SortBy: []query.SortBy{
						query.NewSortBySequence(query.Asc),
					},
				},
				&SingleValueEvent{},
			)
			require.NoError(t, err)

			for _, seq := range sequences {
				seqNum, err := strconv.ParseUint(seq.Cursor, 10, 64)
				require.NoError(t, err)
				seenSequences[seqNum] = true
				if seqNum > lastSeq {
					lastSeq = seqNum
				}
			}

			if len(seenSequences) > initialCount {
				success = true
			} else {
				time.Sleep(2 * time.Second)
			}
		}

		<-done

		t.Logf("Seen %d events (initial: %d, concurrent: %d)", len(seenSequences), initialCount, concurrentCount)
		require.True(t, success, "Failed to see concurrent events after multiple attempts")
		require.Greater(t, len(seenSequences), initialCount, "Should see more than initial events")
		require.LessOrEqual(t, len(seenSequences), initialCount+concurrentCount, "Should not see more events than emitted")
	})
}

func runQueryKeyPersistentTest(t *testing.T, logger logger.Logger, rpcUrl string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	// Setup keystore and txmgr (same as runGetLatestValueTest)
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	rateLimitedClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	getClient := func() (aptos.AptosRpcClient, error) { return rateLimitedClient, nil }
	txmgr, err := txm.New(logger, keystore, txm.DefaultConfigSet, getClient)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	// Deploy the contract (if not already deployed) using the same compilation as runGetLatestValueTest.
	publicKeyHex := hex.EncodeToString([]byte(publicKey))
	compilationResult := testutils.CompileTestModule(t, accountAddress)
	txId := deployContract(t, txmgr, accountAddress.String(), publicKeyHex, compilationResult)
	waitForTx(t, txmgr, txId)

	// Emit a batch of events using echo_with_events (which emits both SingleValueEvent and DoubleValueEvent).
	// For persistent tests we'll use the DoubleValueEvent.
	emitManyEvents(t, txmgr, accountAddress.String(), publicKeyHex, 20)

	// Setup ChainReader configuration for persistent mode using DoubleValueEvent.
	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Events: map[string]*ChainReaderEvent{
					"DoubleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "double_value_events",
						EventAccountAddress:   "", // if empty, defaults to bound contract address
						// No field renames provided.
					},
				},
			},
		},
	}

	// Create a persistent DBStore.
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		// todo: make test run in CI
		t.Skip("Skipping persistent tests as TEST_DB_URL is not set in CI")
	}
	db := sqltest.NewDB(t, dsn)

	// Create ChainReader with persistence enabled.
	chainReader := NewChainReader(logger, rateLimitedClient, config, db)
	binding := commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()}
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	// Allow some time for the emitted events to sync into persistent storage.
	time.Sleep(3 * time.Second)

	// Run subtests for persistent QueryKey.
	t.Run("All events", func(t *testing.T) {
		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
	})

	t.Run("Filter by numeric value", func(t *testing.T) {
		// Retrieve events where number >= 5 and number < 10.
		filter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("number",
					primitives.ValueComparator{Value: uint64(5), Operator: primitives.Gte},
					primitives.ValueComparator{Value: uint64(10), Operator: primitives.Lt},
				),
			},
		}
		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		// Now decode into a *DoubleValueEvent so that "number" is type uint64.
		for _, seq := range seqs {
			evt := seq.Data.(*DoubleValueEvent)
			require.GreaterOrEqual(t, evt.Number, uint64(5))
			require.Less(t, evt.Number, uint64(10))
		}
	})

	t.Run("Filter by text equality", func(t *testing.T) {
		// Expect that some events have text "test7".
		sampleText := "test7"
		filter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("text",
					primitives.ValueComparator{Value: sampleText, Operator: primitives.Eq},
				),
			},
		}
		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		for _, seq := range seqs {
			evt := seq.Data.(*DoubleValueEvent)
			require.Equal(t, sampleText, evt.Text)
		}
	})

	t.Run("Sorted results descending", func(t *testing.T) {
		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{
				Limit: query.CountLimit(10),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Desc),
				},
			},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.Len(t, seqs, 10)

		// Verify descending order based on event_offset.
		for i := 0; i < len(seqs)-1; i++ {
			curr, err := strconv.ParseUint(seqs[i].Cursor, 10, 64)
			require.NoError(t, err)
			next, err := strconv.ParseUint(seqs[i+1].Cursor, 10, 64)
			require.NoError(t, err)
			require.GreaterOrEqual(t, curr, next)
		}
	})

	t.Run("Error cases", func(t *testing.T) {
		// Filtering on a non-existent field should result in empty sequence list.
		invalidFilter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("non_existent_field",
					primitives.ValueComparator{Value: uint64(1), Operator: primitives.Eq},
				),
			},
		}
		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			invalidFilter,
			query.LimitAndSort{},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.Empty(t, seqs)
	})

	t.Run("Filter by renamed numeric value", func(t *testing.T) {
		// Create a new configuration that renames "number" to "RenamedNumber"
		configRenamed := ChainReaderConfig{
			Modules: map[string]*ChainReaderModule{
				"testContract": {
					Name: "echo",
					Events: map[string]*ChainReaderEvent{
						"DoubleValueEvent": {
							EventHandleStructName: "EventStore",
							EventHandleFieldName:  "double_value_events",
							EventAccountAddress:   "", // defaults to bound contract address
							EventFieldRenames: map[string]RenamedField{
								"number": {NewName: "RenamedNumber"},
							},
						},
					},
				},
			},
		}
		chainReaderRenamed := NewChainReader(logger, rateLimitedClient, configRenamed, db)
		bindingRenamed := commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()}
		err := chainReaderRenamed.Bind(context.Background(), []commontypes.BoundContract{bindingRenamed})
		require.NoError(t, err)

		// Emit exactly one event with value 7.
		txId := uuid.New().String()
		err = txmgr.Enqueue(
			txId,
			getSampleTxMetadata(),
			accountAddress.String(),
			publicKeyHex,
			fmt.Sprintf("%s::echo::echo_with_events", accountAddress.String()),
			[]string{},
			[]string{"u64", "0x1::string::String", "vector<u8>"},
			[]any{uint64(7), "test7", []byte{7}},
			true,
		)
		require.NoError(t, err)
		waitForTx(t, txmgr, txId)
		time.Sleep(3 * time.Second) // ensure the event is synced

		// Filter on the renamed field "RenamedNumber"
		filter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("RenamedNumber",
					primitives.ValueComparator{Value: uint64(5), Operator: primitives.Gte},
					primitives.ValueComparator{Value: uint64(10), Operator: primitives.Lt},
				),
			},
		}
		seqs, err := chainReaderRenamed.QueryKey(
			context.Background(),
			bindingRenamed,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEventRenamed{}, // decode into the struct with renamed field
		)
		require.NoError(t, err)
		// Expect exactly one event (the one we just emitted).
		require.Len(t, seqs, 1)
		evt := seqs[0].Data.(*DoubleValueEventRenamed)
		require.Equal(t, uint64(7), evt.RenamedNumber)
	})
}

func TestLoopChainReaderLocal(t *testing.T) {
	lg := logger.Test(t)
	privKey, pubKey, acctAddr := setupTestAccount(t, lg)

	err := testutils.StartAptosNode()
	require.NoError(t, err)
	rpcURL := "http://localhost:8080/v1"
	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)
	err = testutils.FundWithFaucet(lg, client, acctAddr, "http://localhost:8081")
	require.NoError(t, err)
	rlClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	compRes := testutils.CompileTestModule(t, acctAddr)
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privKey)
	getClient := func() (aptos.AptosRpcClient, error) { return rlClient, nil }
	txmgr, err := txm.New(lg, keystore, txm.DefaultConfigSet, getClient)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	txID := uuid.New().String()
	err = txmgr.Enqueue(
		txID,
		getSampleTxMetadata(),
		acctAddr.String(),
		hex.EncodeToString([]byte(pubKey)),
		"0x1::code::publish_package_txn",
		[]string{},
		[]string{"vector<u8>", "vector<vector<u8>>"},
		[]any{compRes.PackageMetadata, compRes.BytecodeModules},
		true,
	)
	require.NoError(t, err)

	confirmed := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		status, err := txmgr.GetStatus(txID)
		require.NoError(t, err)
		if status != commontypes.Unconfirmed {
			confirmed = true
			break
		}
	}
	require.True(t, confirmed, "Contract deploy tx not confirmed")

	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Functions: map[string]*ChainReaderFunction{
					"echo_u64": {
						Params: []AptosFunctionParam{
							{Name: "Value1", Type: "u64"},
						},
					},
					"echo_u32_u64_tuple": {
						Params: []AptosFunctionParam{
							{Name: "Value1", Type: "u32"},
							{Name: "Value2", Type: "u64"},
						},
						ResultTupleToStruct: []string{"first", "second"},
					},
					"get_complex_struct_unwrapped": {
						Name: "get_complex_struct",
						Params: []AptosFunctionParam{
							{Name: "Val", Type: "u64"},
							{Name: "Text", Type: "0x1::string::String"},
						},
						ResultUnwrapStruct: []string{"nested"},
					},
				},
				Events: map[string]*ChainReaderEvent{
					"SingleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "single_value_events",
						EventAccountAddress:   acctAddr.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]RenamedField{
							"value": {NewName: "SingleUintValue"},
						},
					},
					"ComplexStructEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "complex_struct_events",
						EventAccountAddress:   acctAddr.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]RenamedField{
							"flag": {NewName: "RenamedFlag"},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]RenamedField{
									"id":          {NewName: "RenamedId"},
									"description": {NewName: "RenamedDescription"},
								},
							},
							"values": {NewName: "RenamedValues"},
						},
					},
				},
			},
		},
		IsLoopPlugin: true,
	}

	chainReader := NewChainReader(lg, rlClient, config, nil)
	loopReader := loop.NewLoopChainReader(lg, chainReader)
	binding := commontypes.BoundContract{
		Name:    "testContract",
		Address: acctAddr.String(),
	}
	err = loopReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)
	confidenceLevel := primitives.Finalized

	t.Run("GetLatestValue - Simple value read", func(t *testing.T) {
		var ret uint64
		params := struct{ Value1 uint64 }{Value1: 42}
		err := loopReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u64", acctAddr.String()),
			confidenceLevel,
			params,
			&ret,
		)
		require.NoError(t, err)
		require.Equal(t, uint64(42), ret)
	})

	t.Run("GetLatestValue - Wrapped tuple", func(t *testing.T) {
		type WrappedTuple struct {
			First  uint32 `json:"first"`
			Second uint64 `json:"second"`
		}
		var ret WrappedTuple
		params := struct {
			Value1 uint32
			Value2 uint64
		}{Value1: 11, Value2: 22}
		err = loopReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-echo_u32_u64_tuple", acctAddr.String()),
			confidenceLevel,
			params,
			&ret,
		)
		require.NoError(t, err)
		require.Equal(t, uint32(11), ret.First)
		require.Equal(t, uint64(22), ret.Second)
	})

	t.Run("GetLatestValue - Unwrapped complex struct", func(t *testing.T) {
		type UnwrappedStruct struct {
			Id          uint64 `json:"id"`
			Description string `json:"description"`
		}
		var ret UnwrappedStruct

		params := struct {
			Val  uint64
			Text string
		}{Val: 150, Text: "test"}
		err = loopReader.GetLatestValue(
			context.Background(),
			fmt.Sprintf("%s-testContract-get_complex_struct_unwrapped", acctAddr.String()),
			confidenceLevel,
			params,
			&ret,
		)
		require.NoError(t, err)

		require.Equal(t, uint64(150), ret.Id)
		require.Equal(t, "test", ret.Description)
	})

	t.Run("QueryKey - non-persistent mode", func(t *testing.T) {
		ks := testutils.NewTestKeystore(t)
		ks.AddKey(privKey)
		pubKeyHex := hex.EncodeToString([]byte(pubKey))
		txmgr := initTxManager(t, lg, ks, rlClient)
		emitManyEvents(t, txmgr, acctAddr.String(), pubKeyHex, 5)

		t.Run("Sorted Descending", func(t *testing.T) {
			limit := query.LimitAndSort{
				Limit: query.CountLimit(5),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Desc),
				},
			}
			seqs, err := loopReader.QueryKey(context.Background(), binding, query.KeyFilter{Key: "SingleValueEvent"}, limit, &SingleValueEvent{})
			require.NoError(t, err)
			require.Len(t, seqs, 5)
			for i := 0; i < len(seqs)-1; i++ {
				curr := seqs[i].Data.(*SingleValueEvent).SingleUintValue
				next := seqs[i+1].Data.(*SingleValueEvent).SingleUintValue
				require.GreaterOrEqual(t, curr, next)
			}
		})

		t.Run("ComplexStruct Event", func(t *testing.T) {
			limit := query.LimitAndSort{
				Limit: query.CountLimit(5),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Desc),
				},
			}
			seqs, err := loopReader.QueryKey(context.Background(), binding, query.KeyFilter{Key: "ComplexStructEvent"}, limit, &ComplexStruct{})
			require.NoError(t, err)
			require.NotEmpty(t, seqs)
			cs := seqs[0].Data.(*ComplexStruct)
			require.True(t, cs.RenamedFlag, "expected flag to be true")
			require.Equal(t, uint64(4), cs.RenamedNested.RenamedId)
			require.Equal(t, "test4", cs.RenamedNested.RenamedDescription)
			require.Equal(t, []uint64{4, 5}, cs.RenamedValues)
		})

		t.Run("Complex filtering with multiple comparators", func(t *testing.T) {
			filter := query.KeyFilter{
				Key: "SingleValueEvent",
				Expressions: []query.Expression{
					query.Comparator("SingleUintValue",
						primitives.ValueComparator{Value: uint64(3), Operator: primitives.Gte},
						primitives.ValueComparator{Value: uint64(7), Operator: primitives.Lt},
					),
				},
			}
			seqs, err := loopReader.QueryKey(context.Background(), binding, filter, query.LimitAndSort{}, &SingleValueEvent{})
			require.NoError(t, err)
			require.Len(t, seqs, 2)
			for _, seq := range seqs {
				evt := seq.Data.(*SingleValueEvent)
				require.GreaterOrEqual(t, evt.SingleUintValue, uint64(3))
				require.Less(t, evt.SingleUintValue, uint64(7))
			}
		})
	})
}

func TestLoopChainReaderPersistent(t *testing.T) {
	lg := logger.Test(t)
	privKey, pubKey, acctAddr := setupTestAccount(t, lg)

	// Start node and fund account.
	err := testutils.StartAptosNode()
	require.NoError(t, err)
	rpcURL := "http://localhost:8080/v1"
	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)
	err = testutils.FundWithFaucet(lg, client, acctAddr, "http://localhost:8081")
	require.NoError(t, err)
	rlClient := ratelimit.NewRateLimitedClient(client, 100, 30*time.Second)

	// Compile and deploy the contract.
	compRes := testutils.CompileTestModule(t, acctAddr)
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privKey)
	getClient := func() (aptos.AptosRpcClient, error) { return rlClient, nil }
	txmgr, err := txm.New(lg, keystore, txm.DefaultConfigSet, getClient)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(pubKey))
	txID := uuid.New().String()
	err = txmgr.Enqueue(
		txID,
		getSampleTxMetadata(),
		acctAddr.String(),
		publicKeyHex,
		"0x1::code::publish_package_txn",
		[]string{},
		[]string{"vector<u8>", "vector<vector<u8>>"},
		[]any{compRes.PackageMetadata, compRes.BytecodeModules},
		true,
	)
	require.NoError(t, err)
	confirmed := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		status, err := txmgr.GetStatus(txID)
		require.NoError(t, err)
		if status != commontypes.Unconfirmed {
			confirmed = true
			break
		}
	}
	require.True(t, confirmed, "Contract deploy tx not confirmed")

	emitManyEvents(t, txmgr, acctAddr.String(), publicKeyHex, 20)

	// Setup ChainReader configuration using the same event details as other tests.
	config := ChainReaderConfig{
		Modules: map[string]*ChainReaderModule{
			"testContract": {
				Name: "echo",
				Events: map[string]*ChainReaderEvent{
					"SingleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "single_value_events",
						// Use the contract address with the function that returns the event address.
						EventAccountAddress: acctAddr.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]RenamedField{
							"value": {NewName: "SingleUintValue"},
						},
					},
				},
			},
		},
		IsLoopPlugin: true,
	}

	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("Skipping persistent tests as TEST_DB_URL is not set")
	}
	db := sqltest.NewDB(t, dsn)

	// Create ChainReader with persistence enabled.
	chainReader := NewChainReader(lg, rlClient, config, db)
	binding := commontypes.BoundContract{Name: "testContract", Address: acctAddr.String()}
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	loopReader := loop.NewLoopChainReader(lg, chainReader)
	// Re-bind using the loop reader
	err = loopReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	t.Run("QueryKey - Filter by SingleUintValue", func(t *testing.T) {
		filter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(2), Operator: primitives.Gte},
					primitives.ValueComparator{Value: uint64(4), Operator: primitives.Lt},
				),
			},
		}
		// Now call QueryKey on the loopReader, not the chainReader.
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs, "Expected non-empty event results")

		for _, seq := range seqs {
			event := seq.Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, event.SingleUintValue, uint64(2))
			require.Less(t, event.SingleUintValue, uint64(4))
		}
	})

	t.Run("QueryKey - Sorted Results Descending", func(t *testing.T) {
		// Fetch 10 events sorted descending by SingleUintValue
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{
				Limit: query.CountLimit(10),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Desc),
				},
			},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Len(t, seqs, 10)
		for i := 0; i < len(seqs)-1; i++ {
			evtCurrent := seqs[i].Data.(*SingleValueEvent)
			evtNext := seqs[i+1].Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, evtCurrent.SingleUintValue, evtNext.SingleUintValue)
		}
	})

	t.Run("QueryKey - Combined Filtering with Timestamp", func(t *testing.T) {
		// First, fetch all events to pick a mid timestamp.
		allSeqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, allSeqs)
		midTimestamp := allSeqs[len(allSeqs)/2].Head.Timestamp

		filter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Timestamp(midTimestamp, primitives.Gte),
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(10), Operator: primitives.Gte},
				),
			},
		}
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		for _, seq := range seqs {
			require.GreaterOrEqual(t, seq.Head.Timestamp, midTimestamp)
			evt := seq.Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, evt.SingleUintValue, uint64(10))
		}
	})

	t.Run("QueryKey - Multiple Independent Comparators", func(t *testing.T) {
		multiFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(3), Operator: primitives.Gte},
				),
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: uint64(7), Operator: primitives.Lt},
				),
			},
		}
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			multiFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		for _, seq := range seqs {
			evt := seq.Data.(*SingleValueEvent)
			require.GreaterOrEqual(t, evt.SingleUintValue, uint64(3))
			require.Less(t, evt.SingleUintValue, uint64(7))
		}
	})

	t.Run("QueryKey - Error Cases", func(t *testing.T) {
		// Filtering on a non-existent field returns empty results.
		invalidFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("NonExistentField",
					primitives.ValueComparator{Value: uint64(1), Operator: primitives.Eq},
				),
			},
		}
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			invalidFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Empty(t, seqs)

		// Mismatched type should yield an error.
		invalidTypeFilter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("SingleUintValue",
					primitives.ValueComparator{Value: "not a number", Operator: primitives.Eq},
				),
			},
		}
		seqs, err = loopReader.QueryKey(
			context.Background(),
			binding,
			invalidTypeFilter,
			query.LimitAndSort{},
			&SingleValueEvent{},
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot unmarshal string into Go value")
	})
}

func initTxManager(t *testing.T, logger logger.Logger, keystore *testutils.TestKeystore, client aptos.AptosRpcClient) *txm.AptosTxm {
	getClient := func() (aptos.AptosRpcClient, error) { return client, nil }
	txmgr, err := txm.New(logger, keystore, txm.DefaultConfigSet, getClient)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)
	return txmgr
}

func deployContract(t *testing.T, txmgr *txm.AptosTxm, address, publicKeyHex string, compilationResult testutils.CompilationResult) string {
	txId := uuid.New().String()
	err := txmgr.Enqueue(
		txId,
		getSampleTxMetadata(),
		address,
		publicKeyHex,
		"0x1::code::publish_package_txn",
		[]string{},
		[]string{"vector<u8>", "vector<vector<u8>>"},
		[]any{compilationResult.PackageMetadata, compilationResult.BytecodeModules},
		true,
	)
	require.NoError(t, err)
	return txId
}

func waitForTx(t *testing.T, txmgr *txm.AptosTxm, txId string) {
	confirmed := false
	for i := 0; i < 10; i++ {
		time.Sleep(time.Second)
		status, err := txmgr.GetStatus(txId)
		require.NoError(t, err)
		if status != commontypes.Unconfirmed {
			confirmed = true
			break
		}
	}
	require.True(t, confirmed)
}
func getSampleTxMetadata() *commontypes.TxMeta {
	workflowID := "sample-workflow-id"
	return &commontypes.TxMeta{
		WorkflowExecutionID: &workflowID,
		GasLimit:            big.NewInt(21000),
	}
}

type SingleValueEvent struct {
	SingleUintValue uint64
}

type DoubleValueEvent struct {
	Number uint64 `json:"number"`
	Text   string `json:"text"`
}

type VectorVectorEvent struct {
	Values [][]byte `json:"values"`
}

type Nested struct {
	RenamedId          uint64 `json:"RenamedId"`
	RenamedDescription string `json:"RenamedDescription"`
}

type ComplexStruct struct {
	RenamedFlag   bool     `json:"RenamedFlag"`
	RenamedNested Nested   `json:"RenamedNested"`
	RenamedValues []uint64 `json:"RenamedValues"`
}

type DoubleValueEventRenamed struct {
	RenamedNumber uint64 `json:"RenamedNumber"`
	Text          string `json:"text"`
}
