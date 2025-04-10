//go:build integration

package chainreader

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
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

	db := sqltest.NewDB(t, sqltest.TestURL(t))
	chainReader := NewChainReader(logger, rateLimitedClient, config, db)
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

	db := sqltest.NewDB(t, sqltest.TestURL(t))
	chainReader := NewChainReader(logger, rateLimitedClient, config, db)
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{
		{Name: "testContract", Address: accountAddress.String()},
	})
	require.NoError(t, err)

	t.Run("Get all events paginated", func(t *testing.T) {
		pageSize := uint64(5)
		var allEvents []*SingleValueEvent

		for offset := uint64(0); ; offset += pageSize {
			sequences, err := chainReader.QueryKey(
				context.Background(),
				commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
				query.KeyFilter{
					Key: "SingleValueEvent",
					Expressions: []query.Expression{{
						Primitive: &primitives.Comparator{
							Name: "offset",
							ValueComparators: []primitives.ValueComparator{{
								Operator: primitives.Eq,
								Value:    offset,
							}},
						},
					}},
				},
				query.LimitAndSort{Limit: query.CountLimit(pageSize)},
				&SingleValueEvent{},
			)
			require.NoError(t, err)
			if len(sequences) == 0 {
				break
			}
			for _, seq := range sequences {
				allEvents = append(allEvents, seq.Data.(*SingleValueEvent))
			}
		}
		require.Len(t, allEvents, 20)
		for i := 0; i < len(allEvents)-1; i++ {
			require.Less(t, allEvents[i].SingleUintValue, allEvents[i+1].SingleUintValue)
		}
	})

	t.Run("Get newest event with offset", func(t *testing.T) {
		sequences, err := chainReader.QueryKey(
			context.Background(),
			commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()},
			query.KeyFilter{
				Key: "SingleValueEvent",
				Expressions: []query.Expression{{
					Primitive: &primitives.Comparator{
						Name: "offset",
						ValueComparators: []primitives.ValueComparator{{
							Operator: primitives.Eq,
							Value:    uint64(1),
						}},
					},
				}},
			},
			query.LimitAndSort{Limit: query.CountLimit(1)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.Len(t, sequences, 1)
		event := sequences[0].Data.(*SingleValueEvent)
		require.Equal(t, uint64(1), event.SingleUintValue)
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
				},
			},
		},
		IsLoopPlugin: true,
	}

	db := sqltest.NewDB(t, sqltest.TestURL(t))
	chainReader := NewChainReader(lg, rlClient, config, db)
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
