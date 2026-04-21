package fakes

import (
	"context"
	"sync"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	commonCap "github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	aptoscappb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos"
	sdk "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"

	mocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

func TestFakeAptosChain_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	meta := commonCap.RequestMetadata{}

	rpc := mocks.NewAptosRpcClient(t)
	rpc.EXPECT().AccountAPTBalance(mock.Anything).Return(uint64(7), nil)
	rpc.EXPECT().View(mock.Anything).Return([]any{"42"}, nil)
	rpc.EXPECT().TransactionByHash(mock.Anything).Return(&api.Transaction{
		Type: api.TransactionVariantUser, Inner: &api.UserTransaction{Hash: "0x1", Success: true},
	}, nil)
	rpc.EXPECT().AccountTransactions(mock.Anything, mock.Anything, mock.Anything).
		Return([]*api.CommittedTransaction{{Type: api.TransactionVariantUser, Inner: &api.UserTransaction{Hash: "0x1"}}}, nil)
	rpc.EXPECT().BuildTransaction(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&aptos.RawTransaction{}, nil)
	rpc.EXPECT().SimulateTransaction(mock.Anything, mock.Anything).
		Return([]*api.UserTransaction{{Success: true}}, nil)

	fc := newTestAptosChain(t, rpc, true)

	addr := mkAddr32(0xAA)
	validGas := &aptoscappb.GasConfig{MaxGasAmount: 10_000, GasUnitPrice: 100}

	const goroutines = 20
	errCh := make(chan error, goroutines*5)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(5)
		go func() {
			defer wg.Done()
			if _, capErr := fc.AccountAPTBalance(ctx, meta, &aptoscappb.AccountAPTBalanceRequest{Address: addr}); capErr != nil {
				errCh <- capErr
			}
		}()
		go func() {
			defer wg.Done()
			if _, capErr := fc.View(ctx, meta, &aptoscappb.ViewRequest{
				Payload: &aptoscappb.ViewPayload{Module: &aptoscappb.ModuleID{Address: addr, Name: "m"}, Function: "f"},
			}); capErr != nil {
				errCh <- capErr
			}
		}()
		go func() {
			defer wg.Done()
			if _, capErr := fc.TransactionByHash(ctx, meta, &aptoscappb.TransactionByHashRequest{Hash: "0x1"}); capErr != nil {
				errCh <- capErr
			}
		}()
		go func() {
			defer wg.Done()
			if _, capErr := fc.AccountTransactions(ctx, meta, &aptoscappb.AccountTransactionsRequest{Address: addr}); capErr != nil {
				errCh <- capErr
			}
		}()
		go func() {
			defer wg.Done()
			if _, capErr := fc.WriteReport(ctx, meta, &aptoscappb.WriteReportRequest{
				Receiver: addr, GasConfig: validGas, Report: &sdk.ReportResponse{RawReport: []byte("r")},
			}); capErr != nil {
				errCh <- capErr
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		require.NoError(t, e)
	}
}
