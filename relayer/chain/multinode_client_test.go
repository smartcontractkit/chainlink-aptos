package chain_test

import (
	"errors"
	"testing"

	aptos_sdk "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
)

// mockServiceRPC is a minimal mock for ServiceRPCClient (8 methods).
type mockServiceRPC struct {
	mock.Mock
}

func (m *mockServiceRPC) Info() (aptos_sdk.NodeInfo, error) {
	args := m.Called()
	return args.Get(0).(aptos_sdk.NodeInfo), args.Error(1)
}

func (m *mockServiceRPC) GetChainId() (uint8, error) {
	args := m.Called()
	return args.Get(0).(uint8), args.Error(1)
}

func (m *mockServiceRPC) NodeAPIHealthCheck(durationSecs ...uint64) (api.HealthCheckResponse, error) {
	args := m.Called(durationSecs)
	return args.Get(0).(api.HealthCheckResponse), args.Error(1)
}

func (m *mockServiceRPC) Account(address aptos_sdk.AccountAddress, ledgerVersion ...uint64) (aptos_sdk.AccountInfo, error) {
	args := m.Called(address, ledgerVersion)
	return args.Get(0).(aptos_sdk.AccountInfo), args.Error(1)
}

func (m *mockServiceRPC) AccountAPTBalance(address aptos_sdk.AccountAddress, ledgerVersion ...uint64) (uint64, error) {
	args := m.Called(address, ledgerVersion)
	return args.Get(0).(uint64), args.Error(1)
}

func (m *mockServiceRPC) View(payload *aptos_sdk.ViewPayload, ledgerVersion ...uint64) ([]any, error) {
	args := m.Called(payload, ledgerVersion)
	return args.Get(0).([]any), args.Error(1)
}

func (m *mockServiceRPC) TransactionByHash(txnHash string) (*api.Transaction, error) {
	args := m.Called(txnHash)
	return args.Get(0).(*api.Transaction), args.Error(1)
}

func (m *mockServiceRPC) AccountTransactions(address aptos_sdk.AccountAddress, start *uint64, limit *uint64) ([]*api.CommittedTransaction, error) {
	args := m.Called(address, start, limit)
	return args.Get(0).([]*api.CommittedTransaction), args.Error(1)
}

// newTestAdapter wires a MultiNodeClient over a mocked ServiceRPCClient. RPCClientBase is
// left nil: the methods under test (ChainID/Dial/ClientVersion/IsSyncing and promoted domain
// calls) do not touch it.
func newTestAdapter(rpc chain.ServiceRPCClient) *chain.MultiNodeClient {
	return &chain.MultiNodeClient{ServiceRPCClient: rpc}
}

func TestHead(t *testing.T) {
	t.Parallel()

	t.Run("valid head maps height to block number", func(t *testing.T) {
		h := &chain.Head{Height: 1234}
		require.True(t, h.IsValid())
		require.Equal(t, int64(1234), h.BlockNumber())
		require.Nil(t, h.BlockDifficulty())
		require.Nil(t, h.GetTotalDifficulty())
	})

	t.Run("zero height and nil are invalid", func(t *testing.T) {
		require.False(t, (&chain.Head{Height: 0}).IsValid())
		require.Equal(t, int64(0), (&chain.Head{Height: 0}).BlockNumber())
		var nilHead *chain.Head
		require.False(t, nilHead.IsValid())
		require.Equal(t, int64(0), nilHead.BlockNumber())
	})
}

func TestMultiNodeClient_ChainID(t *testing.T) {
	t.Parallel()

	t.Run("returns chain ID as string", func(t *testing.T) {
		m := &mockServiceRPC{}
		m.On("GetChainId").Return(uint8(2), nil)

		id, err := newTestAdapter(m).ChainID(t.Context())
		require.NoError(t, err)
		require.Equal(t, "2", id.String())
		m.AssertExpectations(t)
	})

	t.Run("propagates RPC error", func(t *testing.T) {
		m := &mockServiceRPC{}
		m.On("GetChainId").Return(uint8(0), errors.New("boom"))

		_, err := newTestAdapter(m).ChainID(t.Context())
		require.ErrorContains(t, err, "boom")
		m.AssertExpectations(t)
	})
}

func TestMultiNodeClient_ClientVersion(t *testing.T) {
	t.Parallel()

	m := &mockServiceRPC{}
	m.On("Info").Return(aptos_sdk.NodeInfo{GitHash: "abc123"}, nil)

	v, err := newTestAdapter(m).ClientVersion(t.Context())
	require.NoError(t, err)
	require.Equal(t, "abc123", v)
	m.AssertExpectations(t)
}

func TestMultiNodeClient_IsSyncing(t *testing.T) {
	t.Parallel()
	syncing, err := newTestAdapter(nil).IsSyncing(t.Context())
	require.NoError(t, err)
	require.False(t, syncing)
}

func TestMultiNodeClient_Dial(t *testing.T) {
	t.Parallel()

	t.Run("ok when health succeeds", func(t *testing.T) {
		m := &mockServiceRPC{}
		m.On("NodeAPIHealthCheck", mock.Anything).Return(api.HealthCheckResponse{Message: "ok"}, nil)
		require.NoError(t, newTestAdapter(m).Dial(t.Context()))
		m.AssertExpectations(t)
	})

	t.Run("errors when health fails", func(t *testing.T) {
		m := &mockServiceRPC{}
		m.On("NodeAPIHealthCheck", mock.Anything).Return(api.HealthCheckResponse{}, errors.New("unreachable"))
		require.ErrorContains(t, newTestAdapter(m).Dial(t.Context()), "unreachable")
		m.AssertExpectations(t)
	})
}

func TestMultiNodeClient_ForwardsDomainCall(t *testing.T) {
	t.Parallel()

	m := &mockServiceRPC{}
	addr := aptos_sdk.AccountAddress{}
	m.On("AccountAPTBalance", addr, mock.Anything).Return(uint64(42), nil)

	balance, err := newTestAdapter(m).AccountAPTBalance(addr)
	require.NoError(t, err)
	require.Equal(t, uint64(42), balance)
	m.AssertExpectations(t)
}
