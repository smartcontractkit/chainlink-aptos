package fakes

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	commonCap "github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	aptoscappb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos"
	aptosserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	sdk "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"

	mocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

const testAptosChainSelector uint64 = 4741433654826277352

func testKey(t *testing.T) *crypto.Ed25519PrivateKey {
	t.Helper()
	k, err := crypto.GenerateEd25519PrivateKey()
	require.NoError(t, err)
	return k
}

func testForwarder(t *testing.T) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed("0x1234"))
	return a
}

func newTestAptosChain(t *testing.T, client AptosClient, dryRun bool) *FakeAptosChain {
	t.Helper()
	fc, err := NewFakeAptosChain(logger.Test(t), client, testKey(t),
		testForwarder(t), testAptosChainSelector, dryRun)
	require.NoError(t, err)
	require.NotNil(t, fc)
	return fc
}

func mkAddr32(b byte) []byte { out := make([]byte, 32); out[0] = b; return out }

func TestFakeAptosChain_Construction(t *testing.T) {
	t.Parallel()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	assert.Equal(t, testAptosChainSelector, fc.ChainSelector())
	assert.Contains(t, strings.ToLower(fc.Name()), "aptos")
	assert.NotEmpty(t, fc.Description())
	info, err := fc.Info(t.Context())
	require.NoError(t, err)
	assert.Contains(t, info.ID, "4741433654826277352")
}

func TestFakeAptosChain_InterfaceAssertions(t *testing.T) {
	t.Parallel()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	var _ services.Service = fc
	var _ aptosserver.ClientCapability = fc
	var _ commonCap.ExecutableCapability = fc
}

func TestFakeAptosChain_InitialiseStartsService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)

	require.Error(t, fc.Ready(), "service should not be Ready before Initialise")

	require.NoError(t, fc.Initialise(ctx, core.StandardCapabilitiesDependencies{}))
	require.NoError(t, fc.Ready(), "Initialise must transition service to Started")
	assert.NoError(t, fc.HealthReport()[fc.Name()])

	require.NoError(t, fc.Close())
}

func TestFakeAptosChain_NilClient(t *testing.T) {
	t.Parallel()
	_, err := NewFakeAptosChain(logger.Test(t), nil, testKey(t), testForwarder(t), testAptosChainSelector, false)
	require.Error(t, err)
}

func TestFakeAptosChain_NilKey(t *testing.T) {
	t.Parallel()
	_, err := NewFakeAptosChain(logger.Test(t), mocks.NewAptosRpcClient(t), nil, testForwarder(t), testAptosChainSelector, false)
	require.Error(t, err)
}

func TestFakeAptosChain_AccountAPTBalance(t *testing.T) {
	t.Parallel()
	meta := commonCap.RequestMetadata{}
	ctx := context.Background()

	t.Run("happy", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().AccountAPTBalance(mock.Anything).Return(uint64(1000), nil).Once()
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.AccountAPTBalance(ctx, meta, &aptoscappb.AccountAPTBalanceRequest{Address: mkAddr32(1)})
		require.Nil(t, capErr)
		assert.Equal(t, uint64(1000), reply.Response.Value)
	})

	t.Run("nil request", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.AccountAPTBalance(ctx, meta, nil)
		require.NotNil(t, capErr)
	})

	t.Run("bad address len", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.AccountAPTBalance(ctx, meta, &aptoscappb.AccountAPTBalanceRequest{Address: []byte{1, 2}})
		require.NotNil(t, capErr)
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().AccountAPTBalance(mock.Anything).Return(uint64(0), fmt.Errorf("network down")).Once()
		fc := newTestAptosChain(t, rpc, false)
		_, capErr := fc.AccountAPTBalance(ctx, meta, &aptoscappb.AccountAPTBalanceRequest{Address: mkAddr32(1)})
		require.NotNil(t, capErr)
	})
}

func TestFakeAptosChain_View(t *testing.T) {
	t.Parallel()
	meta := commonCap.RequestMetadata{}
	ctx := context.Background()

	t.Run("happy", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().View(mock.Anything).Return([]any{"42", "x"}, nil).Once()
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.View(ctx, meta, &aptoscappb.ViewRequest{
			Payload: &aptoscappb.ViewPayload{
				Module: &aptoscappb.ModuleID{Address: mkAddr32(0x01), Name: "m"}, Function: "f",
			},
		})
		require.Nil(t, capErr)
		assert.Equal(t, []byte(`["42","x"]`), reply.Response.Data)
	})

	t.Run("nil payload", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.View(ctx, meta, &aptoscappb.ViewRequest{})
		require.NotNil(t, capErr)
	})

	t.Run("rpc err", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().View(mock.Anything).Return(nil, fmt.Errorf("boom")).Once()
		fc := newTestAptosChain(t, rpc, false)
		_, capErr := fc.View(ctx, meta, &aptoscappb.ViewRequest{
			Payload: &aptoscappb.ViewPayload{Module: &aptoscappb.ModuleID{Address: mkAddr32(1), Name: "m"}, Function: "f"},
		})
		require.NotNil(t, capErr)
		// Error must name the failed op.
		assert.Contains(t, capErr.Error(), "aptos view")
		assert.Contains(t, capErr.Error(), "m::f")
		assert.Contains(t, capErr.Error(), "boom")
	})
}

func TestFakeAptosChain_TransactionByHash(t *testing.T) {
	t.Parallel()
	meta := commonCap.RequestMetadata{}
	ctx := context.Background()

	t.Run("found", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().TransactionByHash("0xdeadbeef").Return(&api.Transaction{
			Type:  api.TransactionVariantUser,
			Inner: &api.UserTransaction{Hash: "0xdeadbeef", Version: 7, Success: true},
		}, nil).Once()
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.TransactionByHash(ctx, meta, &aptoscappb.TransactionByHashRequest{Hash: "0xdeadbeef"})
		require.Nil(t, capErr)
		require.NotNil(t, reply.Response.Transaction)
		assert.Equal(t, "0xdeadbeef", reply.Response.Transaction.Hash)
	})

	t.Run("missing", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().TransactionByHash("0xnope").Return(nil, nil).Once()
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.TransactionByHash(ctx, meta, &aptoscappb.TransactionByHashRequest{Hash: "0xnope"})
		require.Nil(t, capErr)
		require.NotNil(t, reply)
		assert.Nil(t, reply.Response.Transaction)
	})

	t.Run("not found (http 404)", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		httpErr := &aptos.HttpError{StatusCode: 404, Status: "404 Not Found", Method: "GET"}
		rpc.EXPECT().TransactionByHash("0xabsent").Return(nil, fmt.Errorf("get transaction api err: %w", httpErr)).Once()
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.TransactionByHash(ctx, meta, &aptoscappb.TransactionByHashRequest{Hash: "0xabsent"})
		require.Nil(t, capErr)
		require.NotNil(t, reply)
		assert.Nil(t, reply.Response.Transaction)
	})

	t.Run("empty hash", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.TransactionByHash(ctx, meta, &aptoscappb.TransactionByHashRequest{Hash: ""})
		require.NotNil(t, capErr)
	})

	t.Run("nil req", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.TransactionByHash(ctx, meta, nil)
		require.NotNil(t, capErr)
	})
}

func TestFakeAptosChain_AccountTransactions(t *testing.T) {
	t.Parallel()
	meta := commonCap.RequestMetadata{}
	ctx := context.Background()

	t.Run("happy passes pagination", func(t *testing.T) {
		t.Parallel()
		rpc := mocks.NewAptosRpcClient(t)
		rpc.EXPECT().AccountTransactions(mock.Anything, mock.Anything, mock.Anything).
			Return([]*api.CommittedTransaction{
				{Type: api.TransactionVariantUser, Inner: &api.UserTransaction{Hash: "0x1"}},
				{Type: api.TransactionVariantUser, Inner: &api.UserTransaction{Hash: "0x2"}},
			}, nil).Once()
		start := uint64(5)
		limit := uint64(3)
		fc := newTestAptosChain(t, rpc, false)
		reply, capErr := fc.AccountTransactions(ctx, meta, &aptoscappb.AccountTransactionsRequest{
			Address: mkAddr32(3), Start: &start, Limit: &limit,
		})
		require.Nil(t, capErr)
		require.Len(t, reply.Response.Transactions, 2)
		assert.Equal(t, "0x1", reply.Response.Transactions[0].Hash)
	})

	t.Run("bad address", func(t *testing.T) {
		t.Parallel()
		fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
		_, capErr := fc.AccountTransactions(ctx, meta, &aptoscappb.AccountTransactionsRequest{Address: []byte{1}})
		require.NotNil(t, capErr)
	})
}

func TestAccountTransactions_DefaultsStartWhenLimitOnly(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	limit := uint64(10)
	var gotStart *uint64
	rpc.EXPECT().AccountTransactions(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ aptos.AccountAddress, start *uint64, _ *uint64) { gotStart = start }).
		Return(nil, nil).Once()
	_, err := accountTransactions(rpc, aptos.AccountAddress{}, nil, &limit)
	require.NoError(t, err)
	require.NotNil(t, gotStart)
	require.Equal(t, uint64(0), *gotStart)
}

func TestAccountTransactions_PassesThroughBothNil(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	var gotStart, gotLimit *uint64
	rpc.EXPECT().AccountTransactions(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ aptos.AccountAddress, start *uint64, limit *uint64) {
			gotStart, gotLimit = start, limit
		}).
		Return(nil, nil).Once()
	_, err := accountTransactions(rpc, aptos.AccountAddress{}, nil, nil)
	require.NoError(t, err)
	require.Nil(t, gotStart)
	require.Nil(t, gotLimit)
}

func TestFakeAptosChain_WriteReport_ValidationErrors(t *testing.T) {
	t.Parallel()
	meta := commonCap.RequestMetadata{}
	ctx := context.Background()
	validGas := &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100}
	validReport := &sdk.ReportResponse{RawReport: []byte("r")}

	cases := map[string]*aptoscappb.WriteReportRequest{
		"nil req":      nil,
		"nil gas":      {Receiver: mkAddr32(0xAA), Report: validReport},
		"nil report":   {Receiver: mkAddr32(0xAA), GasConfig: validGas},
		"bad receiver": {Receiver: []byte{1, 2}, GasConfig: validGas, Report: validReport},
		"nil sig entry": {
			Receiver:  mkAddr32(0xAA),
			GasConfig: validGas,
			Report:    &sdk.ReportResponse{RawReport: []byte("r"), Sigs: []*sdk.AttributedSignature{nil}},
		},
	}
	for name, req := range cases {
		req := req
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
			_, capErr := fc.WriteReport(ctx, meta, req)
			require.NotNil(t, capErr, name)
		})
	}
}

func TestFakeAptosChain_WriteReport_Broadcast_Success(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().BuildSignAndSubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&api.PendingTransaction{Hash: "0xaabb"}, nil).Once()
	rpc.EXPECT().WaitForTransaction("0xaabb").Return(&api.UserTransaction{
		Hash: "0xaabb", Version: 42, Success: true, GasUsed: 150, GasUnitPrice: 100,
	}, nil).Once()
	fc := newTestAptosChain(t, rpc, false)
	reply, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.Nil(t, capErr)
	assert.Equal(t, aptoscappb.TxStatus_TX_STATUS_SUCCESS, reply.Response.TxStatus)
	require.NotNil(t, reply.Response.TxHash)
	assert.Equal(t, "0xaabb", *reply.Response.TxHash)
	require.NotNil(t, reply.Response.TransactionFee)
	assert.Equal(t, uint64(15000), *reply.Response.TransactionFee)
}

func TestFakeAptosChain_WriteReport_Broadcast_FatalVMStatus(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().BuildSignAndSubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&api.PendingTransaction{Hash: "0xffee"}, nil).Once()
	rpc.EXPECT().WaitForTransaction("0xffee").Return(&api.UserTransaction{
		Hash: "0xffee", Success: false, GasUsed: 1, GasUnitPrice: 1,
		VmStatus: "Move abort in 0xdead::receiver: EReject",
	}, nil).Once()
	fc := newTestAptosChain(t, rpc, false)
	reply, _ := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.NotNil(t, reply)
	assert.Equal(t, aptoscappb.TxStatus_TX_STATUS_FATAL, reply.Response.TxStatus)
	require.NotNil(t, reply.Response.ReceiverContractExecutionStatus)
	assert.Equal(t,
		aptoscappb.ReceiverContractExecutionStatus_RECEIVER_CONTRACT_EXECUTION_STATUS_REVERTED,
		*reply.Response.ReceiverContractExecutionStatus)
}

func TestFakeAptosChain_WriteReport_Broadcast_NilFinal(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().BuildSignAndSubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&api.PendingTransaction{Hash: "0xdead"}, nil).Once()
	rpc.EXPECT().WaitForTransaction("0xdead").Return(nil, nil).Once()
	fc := newTestAptosChain(t, rpc, false)
	reply, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.Nil(t, capErr)
	require.NotNil(t, reply)
	assert.Equal(t, aptoscappb.TxStatus_TX_STATUS_FATAL, reply.Response.TxStatus)
	require.NotNil(t, reply.Response.TxHash)
	assert.Equal(t, "0xdead", *reply.Response.TxHash)
	assert.Nil(t, reply.Response.TransactionFee)
	assert.Nil(t, reply.Response.ErrorMessage)
}

func TestFakeAptosChain_WriteReport_Broadcast_NilPending(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().BuildSignAndSubmitTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil).Once()
	fc := newTestAptosChain(t, rpc, false)
	_, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.NotNil(t, capErr)
}

func TestFakeAptosChain_WriteReport_DryRun_NilRawTxn(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().BuildTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, nil).Once()
	fc := newTestAptosChain(t, rpc, true)
	_, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.NotNil(t, capErr)
}

func TestFakeAptosChain_WriteReport_DryRun_Success(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rawTxn := &aptos.RawTransaction{}
	rpc.EXPECT().BuildTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(rawTxn, nil).Once()
	// Dry-run reply must surface Simulate's gas, not zero.
	rpc.EXPECT().SimulateTransaction(rawTxn, mock.Anything).
		Return([]*api.UserTransaction{{Success: true, VmStatus: "Executed", GasUsed: 250, GasUnitPrice: 100}}, nil).Once()
	fc := newTestAptosChain(t, rpc, true)
	reply, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.Nil(t, capErr)
	assert.Equal(t, aptoscappb.TxStatus_TX_STATUS_SUCCESS, reply.Response.TxStatus)
	assert.Nil(t, reply.Response.TxHash)
	require.NotNil(t, reply.Response.TransactionFee)
	assert.Equal(t, uint64(25000), *reply.Response.TransactionFee)
}

func TestFakeAptosChain_WriteReport_DryRun_Reverted(t *testing.T) {
	t.Parallel()
	rpc := mocks.NewAptosRpcClient(t)
	rawTxn := &aptos.RawTransaction{}
	rpc.EXPECT().BuildTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(rawTxn, nil).Once()
	rpc.EXPECT().SimulateTransaction(rawTxn, mock.Anything).
		Return([]*api.UserTransaction{{Success: false, VmStatus: "Move abort in 0xabc::receiver: ENope"}}, nil).Once()
	fc := newTestAptosChain(t, rpc, true)
	reply, capErr := fc.WriteReport(context.Background(), commonCap.RequestMetadata{}, &aptoscappb.WriteReportRequest{
		Receiver:  mkAddr32(0xBB),
		GasConfig: &aptoscappb.GasConfig{MaxGasAmount: 10000, GasUnitPrice: 100},
		Report:    &sdk.ReportResponse{RawReport: []byte("r")},
	})
	require.Nil(t, capErr)
	assert.Equal(t, aptoscappb.TxStatus_TX_STATUS_FATAL, reply.Response.TxStatus)
	require.NotNil(t, reply.Response.ErrorMessage)
	assert.Contains(t, *reply.Response.ErrorMessage, "ENope")
}
