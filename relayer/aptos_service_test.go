package relayer

import (
	"context"
	"testing"

	aptos_sdk "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/chains/aptos"

	chainconfig "github.com/smartcontractkit/chainlink-aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	clientmocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

func TestAptosServiceLedgerVersion(t *testing.T) {
	t.Parallel()

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().Info().Return(aptos_sdk.NodeInfo{LedgerVersionStr: "12345"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	got, err := svc.LedgerVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(12345), got)
}

func TestAptosServiceViewUsesLatestWhenLedgerVersionIsNil(t *testing.T) {
	t.Parallel()

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().View(mock.Anything).Run(func(payload *aptos_sdk.ViewPayload, ledgerVersion ...uint64) {
		require.Equal(t, "balance", payload.Function)
		require.Empty(t, ledgerVersion)
	}).Return([]any{"ok"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.View(context.Background(), aptos.ViewRequest{
		Payload: &aptos.ViewPayload{
			Module: aptos.ModuleID{
				Address: aptos.AccountAddress{1},
				Name:    "coin",
			},
			Function: "balance",
		},
	})
	require.NoError(t, err)
	require.JSONEq(t, `["ok"]`, string(reply.Data))
}

func TestAptosServiceViewUsesRequestedLedgerVersion(t *testing.T) {
	t.Parallel()

	const ledgerVersion = uint64(77)
	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().View(mock.Anything, ledgerVersion).Run(func(payload *aptos_sdk.ViewPayload, versions ...uint64) {
		require.Equal(t, "balance", payload.Function)
		require.Len(t, versions, 1)
		require.Equal(t, ledgerVersion, versions[0])
	}).Return([]any{"ok"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.View(context.Background(), aptos.ViewRequest{
		Payload: &aptos.ViewPayload{
			Module: aptos.ModuleID{
				Address: aptos.AccountAddress{1},
				Name:    "coin",
			},
			Function: "balance",
		},
		LedgerVersion: ptrUint64(ledgerVersion),
	})
	require.NoError(t, err)
	require.JSONEq(t, `["ok"]`, string(reply.Data))
}

func ptrUint64(v uint64) *uint64 {
	return &v
}

func TestAptosServiceAccountTransactionsYoungAccount(t *testing.T) {
	t.Parallel()

	var addr aptos.AccountAddress
	addr[31] = 0xEE
	sdkAddr := aptos_sdk.AccountAddress(addr[:])
	requestedLimit := uint64(10)

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().Account(sdkAddr).Return(aptos_sdk.AccountInfo{SequenceNumberStr: "4"}, nil).Once()
	client.EXPECT().AccountTransactions(sdkAddr, mock.Anything, mock.Anything).
		Run(func(_ aptos_sdk.AccountAddress, start *uint64, limit *uint64) {
			require.NotNil(t, start)
			require.NotNil(t, limit)
			require.Equal(t, uint64(0), *start)
			require.Equal(t, uint64(4), *limit)
		}).
		Return([]*api.CommittedTransaction{}, nil).
		Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.AccountTransactions(context.Background(), aptos.AccountTransactionsRequest{
		Address: addr,
		Limit:   &requestedLimit,
	})
	require.NoError(t, err)
	require.Empty(t, reply.Transactions)
}

func TestAptosServiceAccountTransactionsUsesLatestWindowForLimitOnlyQuery(t *testing.T) {
	t.Parallel()

	var addr aptos.AccountAddress
	addr[31] = 0xEE
	sdkAddr := aptos_sdk.AccountAddress(addr[:])
	requestedLimit := uint64(10)

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().Account(sdkAddr).Return(aptos_sdk.AccountInfo{SequenceNumberStr: "25"}, nil).Once()
	client.EXPECT().AccountTransactions(sdkAddr, mock.Anything, mock.Anything).
		Run(func(_ aptos_sdk.AccountAddress, start *uint64, limit *uint64) {
			require.NotNil(t, start)
			require.NotNil(t, limit)
			require.Equal(t, uint64(15), *start)
			require.Equal(t, uint64(10), *limit)
		}).
		Return([]*api.CommittedTransaction{}, nil).
		Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.AccountTransactions(context.Background(), aptos.AccountTransactionsRequest{
		Address: addr,
		Limit:   &requestedLimit,
	})
	require.NoError(t, err)
	require.Empty(t, reply.Transactions)
}

func TestAptosServiceAccountTransactionsReturnsEmptyForZeroSequenceNumber(t *testing.T) {
	t.Parallel()

	var addr aptos.AccountAddress
	addr[31] = 0xEE
	sdkAddr := aptos_sdk.AccountAddress(addr[:])
	requestedLimit := uint64(10)

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().Account(sdkAddr).Return(aptos_sdk.AccountInfo{SequenceNumberStr: "0"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.AccountTransactions(context.Background(), aptos.AccountTransactionsRequest{
		Address: addr,
		Limit:   &requestedLimit,
	})
	require.NoError(t, err)
	require.Empty(t, reply.Transactions)
}

func TestAptosServiceAccountTransactionsPreservesExplicitStart(t *testing.T) {
	t.Parallel()

	var addr aptos.AccountAddress
	addr[31] = 0xEE
	sdkAddr := aptos_sdk.AccountAddress(addr[:])
	start := uint64(3)
	limit := uint64(10)

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().AccountTransactions(sdkAddr,
		mock.MatchedBy(func(s *uint64) bool { return s != nil && *s == start }),
		mock.MatchedBy(func(l *uint64) bool { return l != nil && *l == limit }),
	).Return([]*api.CommittedTransaction{}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.AccountTransactions(context.Background(), aptos.AccountTransactionsRequest{
		Address: addr,
		Start:   &start,
		Limit:   &limit,
	})
	require.NoError(t, err)
	require.Empty(t, reply.Transactions)
}

type testChain struct {
	commontypes.UnimplementedChainService
	client aptos_sdk.AptosRpcClient
}

func (t testChain) Start(context.Context) error {
	return nil
}

func (t testChain) Close() error {
	return nil
}

func (t testChain) Ready() error {
	return nil
}

func (t testChain) Name() string {
	return "test-chain"
}

func (t testChain) HealthReport() map[string]error {
	return map[string]error{}
}

func (t testChain) ID() string {
	return "1"
}

func (t testChain) Config() *chainconfig.TOMLConfig {
	return &chainconfig.TOMLConfig{}
}

func (t testChain) DataSource() sqlutil.DataSource {
	return nil
}

func (t testChain) TxManager() *txm.AptosTxm {
	return nil
}

func (t testChain) LogPoller() *logpoller.AptosLogPoller {
	return nil
}

func (t testChain) GetClient() (aptos_sdk.AptosRpcClient, error) {
	return t.client, nil
}

func (t testChain) KeyStore() loop.Keystore {
	return nil
}
