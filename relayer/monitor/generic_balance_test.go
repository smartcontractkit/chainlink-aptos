package monitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

// mockBalanceClient implements GenericBalanceClient for testing.
type mockBalanceClient struct {
	balances map[string]float64
	err      error
}

func (m *mockBalanceClient) GetAccountBalance(addr string) (float64, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.balances[addr], nil
}

func testOpts(t *testing.T) GenericBalanceMonitorOpts {
	t.Helper()
	ks := mocks.NewKeystore(t)
	ks.EXPECT().Accounts(mock.Anything).Return([]string{"key1"}, nil).Maybe()

	return GenericBalanceMonitorOpts{
		ChainInfo:           types.ChainInfo{ChainFamilyName: "aptos", ChainID: "testnet", NetworkName: "testnet", NetworkNameFull: "aptos-testnet"},
		ChainNativeCurrency: "APT",
		Config:              GenericBalanceConfig{BalancePollPeriod: config.MustNewDuration(100 * time.Millisecond)},
		Logger:              logger.Test(t),
		Keystore:            ks,
		NewGenericBalanceClient: func() (GenericBalanceClient, error) {
			return &mockBalanceClient{balances: map[string]float64{"addr1": 1.5}}, nil
		},
		KeyToAccountMapper: func(_ context.Context, pk string) (string, error) {
			return "addr" + pk[len(pk)-1:], nil // key1 -> addr1
		},
	}
}

func TestNewGenericBalanceMonitor(t *testing.T) {
	t.Parallel()

	t.Run("creates monitor successfully", func(t *testing.T) {
		t.Parallel()
		svc, err := NewGenericBalanceMonitor(testOpts(t))
		require.NoError(t, err)
		require.NotNil(t, svc)
	})
}

func TestGenericBalanceMonitorStartClose(t *testing.T) {
	t.Parallel()
	svc, err := NewGenericBalanceMonitor(testOpts(t))
	require.NoError(t, err)

	err = svc.Start(context.Background())
	require.NoError(t, err)
	defer svc.Close()
}

func TestGenericBalanceMonitorHealthReport(t *testing.T) {
	t.Parallel()
	svc, err := NewGenericBalanceMonitor(testOpts(t))
	require.NoError(t, err)

	err = svc.Start(context.Background())
	require.NoError(t, err)
	defer svc.Close()

	m := svc.(*genericBalanceMonitor)
	report := m.HealthReport()
	require.Len(t, report, 1)
	for _, v := range report {
		assert.NoError(t, v)
	}
}

func TestUpdateBalances(t *testing.T) {
	t.Parallel()

	t.Run("updates balance for each account", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		ks := mocks.NewKeystore(t)
		ks.EXPECT().Accounts(mock.Anything).Return([]string{"key1", "key2"}, nil)
		opts.Keystore = ks
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			return &mockBalanceClient{balances: map[string]float64{"addr1": 1.5, "addr2": 3.0}}, nil
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		updates := map[string]float64{}
		m.updateFn = func(_ context.Context, acc string, balance float64) {
			updates[acc] = balance
		}

		m.updateBalances(context.Background())
		assert.Equal(t, map[string]float64{"addr1": 1.5, "addr2": 3.0}, updates)
	})

	t.Run("handles keystore error", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		ks := mocks.NewKeystore(t)
		ks.EXPECT().Accounts(mock.Anything).Return(nil, errors.New("keystore fail"))
		opts.Keystore = ks

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		called := false
		m.updateFn = func(context.Context, string, float64) { called = true }
		m.updateBalances(context.Background())
		assert.False(t, called)
	})

	t.Run("handles empty keystore", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		ks := mocks.NewKeystore(t)
		ks.EXPECT().Accounts(mock.Anything).Return([]string{}, nil)
		opts.Keystore = ks

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		called := false
		m.updateFn = func(context.Context, string, float64) { called = true }
		m.updateBalances(context.Background())
		assert.False(t, called)
	})

	t.Run("handles client creation error", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			return nil, errors.New("client fail")
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		called := false
		m.updateFn = func(context.Context, string, float64) { called = true }
		m.updateBalances(context.Background())
		assert.False(t, called)
	})

	t.Run("handles key mapping error", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		opts.KeyToAccountMapper = func(context.Context, string) (string, error) {
			return "", errors.New("mapping fail")
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		called := false
		m.updateFn = func(context.Context, string, float64) { called = true }
		m.updateBalances(context.Background())
		assert.False(t, called)
	})

	t.Run("handles balance fetch error and continues", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		ks := mocks.NewKeystore(t)
		ks.EXPECT().Accounts(mock.Anything).Return([]string{"key1", "key2"}, nil)
		opts.Keystore = ks

		callCount := 0
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			return &errOnFirstClient{
				errAddr:  "addr1",
				balances: map[string]float64{"addr2": 5.0},
			}, nil
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		m.updateFn = func(_ context.Context, acc string, balance float64) {
			callCount++
			assert.Equal(t, "addr2", acc)
			assert.Equal(t, 5.0, balance)
		}
		m.updateBalances(context.Background())
		assert.Equal(t, 1, callCount)
	})

	t.Run("resets reader when no balances retrieved", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		ks := mocks.NewKeystore(t)
		ks.EXPECT().Accounts(mock.Anything).Return([]string{"key1"}, nil)
		opts.Keystore = ks
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			return &mockBalanceClient{err: errors.New("rpc error")}, nil
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)
		m.updateFn = func(context.Context, string, float64) {}

		// Prime the reader
		_, err = m.getReader()
		require.NoError(t, err)
		require.NotNil(t, m.reader)

		m.updateBalances(context.Background())
		assert.Nil(t, m.reader, "reader should be reset when no balances retrieved")
	})
}

func TestGetReader(t *testing.T) {
	t.Parallel()

	t.Run("caches client", func(t *testing.T) {
		t.Parallel()
		createCount := 0
		opts := testOpts(t)
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			createCount++
			return &mockBalanceClient{}, nil
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		r1, err := m.getReader()
		require.NoError(t, err)
		r2, err := m.getReader()
		require.NoError(t, err)

		assert.Same(t, r1, r2)
		assert.Equal(t, 1, createCount)
	})

	t.Run("returns error from factory", func(t *testing.T) {
		t.Parallel()
		opts := testOpts(t)
		opts.NewGenericBalanceClient = func() (GenericBalanceClient, error) {
			return nil, errors.New("factory error")
		}

		svc, err := NewGenericBalanceMonitor(opts)
		require.NoError(t, err)
		m := svc.(*genericBalanceMonitor)

		_, err = m.getReader()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "factory error")
	})
}

// errOnFirstClient returns an error for a specific address but succeeds for others.
type errOnFirstClient struct {
	errAddr  string
	balances map[string]float64
}

func (c *errOnFirstClient) GetAccountBalance(addr string) (float64, error) {
	if addr == c.errAddr {
		return 0, errors.New("balance error for " + addr)
	}
	return c.balances[addr], nil
}
