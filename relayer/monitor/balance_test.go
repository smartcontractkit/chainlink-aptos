package monitor

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

func TestOctaToAPT(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		octa     uint64
		expected float64
	}{
		{"zero", 0, 0},
		{"one APT", 100_000_000, 1.0},
		{"fractional", 50_000_000, 0.5},
		{"large", 1_000_000_000_000, 10_000.0},
		{"one octa", 1, 1e-8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.InDelta(t, tt.expected, octaToAPT(tt.octa), 1e-12)
		})
	}
}

func TestBalanceClientGetAccountBalance(t *testing.T) {
	t.Parallel()

	t.Run("valid address returns balance", func(t *testing.T) {
		t.Parallel()
		addr := aptos.AccountOne
		m := mocks.NewAptosRpcClient(t)
		m.EXPECT().AccountAPTBalance(addr).Return(uint64(250_000_000), nil)

		balance, err := balanceClient{client: m}.GetAccountBalance(addr.String())
		require.NoError(t, err)
		assert.InDelta(t, 2.5, balance, 1e-12)
	})

	t.Run("invalid address returns error", func(t *testing.T) {
		t.Parallel()
		m := mocks.NewAptosRpcClient(t)
		_, err := balanceClient{client: m}.GetAccountBalance("not-valid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse address")
	})

	t.Run("rpc error propagated", func(t *testing.T) {
		t.Parallel()
		m := mocks.NewAptosRpcClient(t)
		m.EXPECT().AccountAPTBalance(mock.Anything).Return(uint64(0), assert.AnError)

		_, err := balanceClient{client: m}.GetAccountBalance(aptos.AccountOne.String())
		require.ErrorIs(t, err, assert.AnError)
	})
}
