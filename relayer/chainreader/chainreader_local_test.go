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
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	_ "github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil/sqltest"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/loop"
	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
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

	t.Run("QueryKeyPersistent", func(t *testing.T) {
		runQueryKeyPersistentTest(t, logger, rpcUrl, accountAddress, publicKey, privateKey)
	})
}

func setupTestDatabase(t *testing.T, db *sqlx.DB) {
	createSchemaSQL := `CREATE SCHEMA IF NOT EXISTS aptos;`
	_, err := db.Exec(createSchemaSQL)
	require.NoError(t, err)

	createEventsTableSQL := `
    CREATE TABLE IF NOT EXISTS aptos.events (
        id BIGSERIAL PRIMARY KEY,
        event_account_address TEXT NOT NULL,
        event_handle TEXT NOT NULL,
        event_field_name TEXT NOT NULL,
        event_offset BIGINT NOT NULL,
        tx_version BIGINT NOT NULL,
        block_height TEXT NOT NULL,
        block_hash BYTEA NOT NULL,
        block_timestamp BIGINT NOT NULL,
        data JSONB NOT NULL,
        UNIQUE (event_account_address, event_handle, event_field_name, event_offset, tx_version)
    );`
	_, err = db.Exec(createEventsTableSQL)
	require.NoError(t, err)

	createIndexSQL := `
    CREATE INDEX IF NOT EXISTS idx_events_account_handle_offset
    ON aptos.events(event_account_address, event_handle, event_field_name, tx_version, event_offset);`
	_, err = db.Exec(createIndexSQL)
	require.NoError(t, err)

	createTransmitterSeqSQL := `
    CREATE TABLE IF NOT EXISTS aptos.transmitter_sequence_nums (
        id BIGSERIAL PRIMARY KEY,
        transmitter_address TEXT NOT NULL,
        sequence_number BIGINT NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (transmitter_address)
    );`
	_, err = db.Exec(createTransmitterSeqSQL)
	require.NoError(t, err)
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

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rateLimitedClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcUrl, 100, 30*time.Second)

	getClient := func() (aptos.AptosRpcClient, error) { return rateLimitedClient, nil }

	txmConfig := txm.DefaultConfigSet
	txmgr, err := txm.New(logger, keystore, txmConfig, getClient, chainInfo.ChainID)
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
	waitForTx(t, txmgr, txId)

	config := crconfig.ChainReaderConfig{
		Modules: map[string]*crconfig.ChainReaderModule{
			"testContract": {
				Name: "echo",
				Functions: map[string]*crconfig.ChainReaderFunction{
					"echo_u64": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "u64",
							},
						},
					},
					"echo_u32_u64_tuple": {
						Params: []crconfig.AptosFunctionParam{
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
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "0x1::string::String",
							},
						},
					},
					"echo_byte_vector": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<u8>",
							},
						},
					},
					"echo_u32_vector": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<u32>",
							},
						},
					},
					"echo_byte_vector_vector": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "vector<vector<u8>>",
							},
						},
					},
					"echo_u256": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Value1",
								Type: "u256",
							},
						},
					},
					"get_complex_struct": {
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Val",
								Type: "u64",
							},
							{
								Name: "Text",
								Type: "0x1::string::String",
							},
						},
						ResultFieldRenames: map[string]crconfig.RenamedField{
							"flag": {
								NewName: "RenamedFlag",
							},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]crconfig.RenamedField{
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
						Params: []crconfig.AptosFunctionParam{
							{
								Name: "Val",
								Type: "u64",
							},
							{
								Name: "Text",
								Type: "0x1::string::String",
							},
						},
						ResultFieldRenames: map[string]crconfig.RenamedField{
							"flag": {
								NewName: "RenamedFlag",
							},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]crconfig.RenamedField{
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
						Params: []crconfig.AptosFunctionParam{
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

	logPoller, err := logpoller.NewLogPoller(logger, chainInfo, getClient, nil, nil)
	require.NoError(t, err)

	chainReader := NewChainReader(logger, rateLimitedClient, config, nil, logPoller)
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

	time.Sleep(15 * time.Second) // Wait for events to be processed
}

func runQueryKeyPersistentTest(t *testing.T, logger logger.Logger, rpcUrl string, accountAddress aptos.AccountAddress, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		// todo: make test run in CI
		t.Skip("Skipping persistent tests as TEST_DB_URL is not set in CI")
	}
	db := sqltest.NewDB(t, dsn)
	setupTestDatabase(t, db)

	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privateKey)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rateLimitedClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcUrl, 100, 30*time.Second)
	getClient := func() (aptos.AptosRpcClient, error) { return rateLimitedClient, nil }

	txmgr, err := txm.New(logger, keystore, txm.DefaultConfigSet, getClient, chainInfo.ChainID)
	require.NoError(t, err)
	err = txmgr.Start(context.Background())
	require.NoError(t, err)

	publicKeyHex := hex.EncodeToString([]byte(publicKey))
	compilationResult := testutils.CompileTestModule(t, accountAddress)
	txId := deployContract(t, txmgr, accountAddress.String(), publicKeyHex, compilationResult)
	waitForTx(t, txmgr, txId)

	config := crconfig.ChainReaderConfig{
		Modules: map[string]*crconfig.ChainReaderModule{
			"testContract": {
				Name: "echo",
				Events: map[string]*crconfig.ChainReaderEvent{
					"DoubleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "double_value_events",
						EventAccountAddress:   "",
					},
					"SingleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "single_value_events",
						EventAccountAddress:   "",
					},
				},
			},
		},
	}

	logPoller, err := logpoller.NewLogPoller(logger, chainInfo, getClient, db, nil)
	require.NoError(t, err)
	err = logPoller.Start(context.Background())
	require.NoError(t, err)

	chainReader := NewChainReader(logger, rateLimitedClient, config, db, logPoller)
	binding := commontypes.BoundContract{Name: "testContract", Address: accountAddress.String()}
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	emitManyEvents(t, txmgr, accountAddress.String(), publicKeyHex, 20)

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

	t.Run("Events stored separately", func(t *testing.T) {
		doubleSeqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, doubleSeqs, "Expected DoubleValueEvent events")

		singleSeqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "SingleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, singleSeqs, "Expected SingleValueEvent events")

		for _, seq := range doubleSeqs {
			_, ok := seq.Data.(*DoubleValueEvent)
			require.True(t, ok, "Expected DoubleValueEvent type")
		}

		for _, seq := range singleSeqs {
			_, ok := seq.Data.(*SingleValueEvent)
			require.True(t, ok, "Expected SingleValueEvent type")
		}
	})

	t.Run("Filter by numeric value", func(t *testing.T) {
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
		for _, seq := range seqs {
			evt := seq.Data.(*DoubleValueEvent)
			require.GreaterOrEqual(t, evt.Number, uint64(5))
			require.Less(t, evt.Number, uint64(10))
		}
	})

	t.Run("Filter by text equality", func(t *testing.T) {
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
		extReader, ok := chainReader.(ExtendedContractReader)
		require.True(t, ok, "chainReader does not implement ExtendedContractReader")

		enrichedSeqs, err := extReader.QueryKeyWithMetadata(
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
		require.Len(t, enrichedSeqs, 10)

		for i := 0; i < len(enrichedSeqs)-1; i++ {
			curr := enrichedSeqs[i].TxVersion
			next := enrichedSeqs[i+1].TxVersion
			require.Greater(t, curr, next, "Expected tx_version in descending order")
		}
	})

	t.Run("Error cases", func(t *testing.T) {
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

	t.Run("Get events using timestamp filter", func(t *testing.T) {
		allSeqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, allSeqs)

		midIdx := len(allSeqs) / 2
		midTimestamp := allSeqs[midIdx].Head.Timestamp

		filter := query.KeyFilter{
			Key:         "DoubleValueEvent",
			Expressions: []query.Expression{query.Timestamp(midTimestamp, primitives.Gte)},
		}

		filteredSeqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, filteredSeqs)

		for _, seq := range filteredSeqs {
			require.GreaterOrEqual(t, seq.Head.Timestamp, midTimestamp)
		}
	})

	t.Run("Complex filtering with multiple comparators", func(t *testing.T) {
		filter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Comparator("number",
					primitives.ValueComparator{Value: uint64(3), Operator: primitives.Gte},
					primitives.ValueComparator{Value: uint64(7), Operator: primitives.Lt},
				),
			},
		}

		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		for _, seq := range seqs {
			evt := seq.Data.(*DoubleValueEvent)
			require.GreaterOrEqual(t, evt.Number, uint64(3))
			require.Less(t, evt.Number, uint64(7))
		}
	})

	t.Run("Combined filtering with timestamp", func(t *testing.T) {
		allSeqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, allSeqs)

		midTs := allSeqs[len(allSeqs)/2].Head.Timestamp

		combinedFilter := query.KeyFilter{
			Key: "DoubleValueEvent",
			Expressions: []query.Expression{
				query.Timestamp(midTs, primitives.Gte),
				query.Comparator("number",
					primitives.ValueComparator{Value: uint64(15), Operator: primitives.Lte},
				),
			},
		}

		seqs, err := chainReader.QueryKey(
			context.Background(),
			binding,
			combinedFilter,
			query.LimitAndSort{},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)
		for _, seq := range seqs {
			evt := seq.Data.(*DoubleValueEvent)
			require.LessOrEqual(t, evt.Number, uint64(15))
			require.GreaterOrEqual(t, seq.Head.Timestamp, midTs)
		}
	})

	t.Run("QueryKeyWithMetadata - Enriched event metadata", func(t *testing.T) {
		extReader, ok := chainReader.(ExtendedContractReader)
		require.True(t, ok, "chainReader does not implement ExtendedContractReader")

		enrichedSeqs, err := extReader.QueryKeyWithMetadata(
			context.Background(),
			binding,
			query.KeyFilter{Key: "DoubleValueEvent"},
			query.LimitAndSort{Limit: query.CountLimit(10)},
			&DoubleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, enrichedSeqs, "expected at least one enriched event")

		for _, seqMeta := range enrichedSeqs {
			require.NotEmpty(t, seqMeta.Sequence.Cursor, "cursor should be set")
			require.NotEqual(t, uint64(0), seqMeta.TxVersion, "tx version must be non zero")
			require.NotEmpty(t, seqMeta.TxHash, "tx hash must not be empty")
		}
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

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rlClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcURL, 100, 30*time.Second)

	// Compile and deploy the contract.
	compRes := testutils.CompileTestModule(t, acctAddr)
	keystore := testutils.NewTestKeystore(t)
	keystore.AddKey(privKey)
	getClient := func() (aptos.AptosRpcClient, error) { return rlClient, nil }
	txmgr, err := txm.New(lg, keystore, txm.DefaultConfigSet, getClient, chainInfo.ChainID)
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
	waitForTx(t, txmgr, txID)

	config := crconfig.ChainReaderConfig{
		Modules: map[string]*crconfig.ChainReaderModule{
			"testContract": {
				Name: "echo",
				Functions: map[string]*crconfig.ChainReaderFunction{
					"echo_u64": {
						Params: []crconfig.AptosFunctionParam{
							{Name: "Value1", Type: "u64"},
						},
					},
					"echo_u32_u64_tuple": {
						Params: []crconfig.AptosFunctionParam{
							{Name: "Value1", Type: "u32"},
							{Name: "Value2", Type: "u64"},
						},
						ResultTupleToStruct: []string{"first", "second"},
					},
					"get_complex_struct_unwrapped": {
						Name: "get_complex_struct",
						Params: []crconfig.AptosFunctionParam{
							{Name: "Val", Type: "u64"},
							{Name: "Text", Type: "0x1::string::String"},
						},
						ResultUnwrapStruct: []string{"nested"},
					},
				},
				Events: map[string]*crconfig.ChainReaderEvent{
					"SingleValueEvent": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "single_value_events",
						EventAccountAddress:   acctAddr.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]crconfig.RenamedField{
							"value": {NewName: "SingleUintValue"},
						},
					},
					"ComplexStruct": {
						EventHandleStructName: "EventStore",
						EventHandleFieldName:  "complex_struct_events",
						EventAccountAddress:   acctAddr.String() + "::echo::get_event_address",
						EventFieldRenames: map[string]crconfig.RenamedField{
							"flag": {NewName: "RenamedFlag"},
							"nested": {
								NewName: "RenamedNested",
								SubFieldRenames: map[string]crconfig.RenamedField{
									"id":          {NewName: "RenamedId"},
									"description": {NewName: "RenamedDescription"},
								},
							},
							"values": {NewName: "RenamedValues"},
						},
						EventFilterRenames: map[string]string{
							"NestedID": "RenamedNested.RenamedId",
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
	setupTestDatabase(t, db)

	// Create ChainReader with persistence enabled.
	logPoller, err := logpoller.NewLogPoller(lg, chainInfo, getClient, db, nil)
	require.NoError(t, err)
	err = logPoller.Start(context.Background())
	require.NoError(t, err)

	chainReader := NewChainReader(lg, rlClient, config, db, logPoller)
	binding := commontypes.BoundContract{Name: "testContract", Address: acctAddr.String()}
	err = chainReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	emitManyEvents(t, txmgr, acctAddr.String(), publicKeyHex, 20)

	loopReader := loop.NewLoopChainReader(lg, chainReader)
	// Re-bind using the loop reader
	err = loopReader.Bind(context.Background(), []commontypes.BoundContract{binding})
	require.NoError(t, err)

	// Declare the confidence level used with GetLatestValue.
	confidenceLevel := primitives.Finalized

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

	t.Run("Filter by nested path via EventFilterRenames - single event", func(t *testing.T) {
		filter := query.KeyFilter{
			Key: "ComplexStruct",
			Expressions: []query.Expression{
				query.Comparator("NestedID",
					primitives.ValueComparator{Value: uint64(10), Operator: primitives.Eq},
				),
			},
		}

		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(1)},
			&ComplexStruct{},
		)
		require.NoError(t, err)
		require.Len(t, seqs, 1, "Expected exactly one matching event")

		evt := seqs[0].Data.(*ComplexStruct)
		require.Equal(t, uint64(10), evt.RenamedNested.RenamedId, "Event should have nested ID value of 10")
	})

	t.Run("QueryKey - Complex Boolean Filter with Nested AND/OR", func(t *testing.T) {
		// Create a complex filter like:
		// (SingleUintValue >= 2 AND SingleUintValue < 5) OR (SingleUintValue >= 15 AND SingleUintValue < 18)
		// This should match events with values 2,3,4,15,16,17
		filter := query.KeyFilter{
			Key: "SingleValueEvent",
			Expressions: []query.Expression{
				query.Or(
					query.And(
						query.Comparator("SingleUintValue",
							primitives.ValueComparator{Value: uint64(2), Operator: primitives.Gte},
						),
						query.Comparator("SingleUintValue",
							primitives.ValueComparator{Value: uint64(5), Operator: primitives.Lt},
						),
					),
					query.And(
						query.Comparator("SingleUintValue",
							primitives.ValueComparator{Value: uint64(15), Operator: primitives.Gte},
						),
						query.Comparator("SingleUintValue",
							primitives.ValueComparator{Value: uint64(18), Operator: primitives.Lt},
						),
					),
				),
			},
		}

		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{
				Limit: query.CountLimit(100),
				SortBy: []query.SortBy{
					query.NewSortBySequence(query.Asc),
				},
			},
			&SingleValueEvent{},
		)
		require.NoError(t, err)
		require.NotEmpty(t, seqs)

		var values []uint64
		for _, seq := range seqs {
			evt := seq.Data.(*SingleValueEvent)
			values = append(values, evt.SingleUintValue)
		}

		expectedValues := []uint64{2, 3, 4, 15, 16, 17}
		require.Len(t, seqs, len(expectedValues))
		require.ElementsMatch(t, expectedValues, values)
	})

	t.Run("Filter by nested path via EventFilterRenames - nested boolean", func(t *testing.T) {
		// This filter will test renaming inside nested boolean expressions.
		// (NestedID >= 2 AND NestedID < 5) OR (NestedID >= 15 AND NestedID < 18)
		filter := query.KeyFilter{
			Key: "ComplexStruct",
			Expressions: []query.Expression{
				query.Or(
					query.And(
						query.Comparator("NestedID",
							primitives.ValueComparator{Value: uint64(2), Operator: primitives.Gte},
							primitives.ValueComparator{Value: uint64(5), Operator: primitives.Lt},
						),
					),
					query.And(
						query.Comparator("NestedID",
							primitives.ValueComparator{Value: uint64(15), Operator: primitives.Gte},
							primitives.ValueComparator{Value: uint64(18), Operator: primitives.Lt},
						),
					),
				),
			},
		}
		seqs, err := loopReader.QueryKey(
			context.Background(),
			binding,
			filter,
			query.LimitAndSort{Limit: query.CountLimit(100)},
			&ComplexStruct{},
		)
		require.NoError(t, err)

		var ids []uint64
		for _, seq := range seqs {
			cs, ok := seq.Data.(*ComplexStruct)
			require.True(t, ok)
			ids = append(ids, cs.RenamedNested.RenamedId)
		}
		require.ElementsMatch(t, []uint64{2, 3, 4, 15, 16, 17}, ids)
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
		if status == commontypes.Finalized {
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
		GasLimit:            big.NewInt(210000),
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
