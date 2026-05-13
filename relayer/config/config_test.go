package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const baseTOML = `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
`

func TestTOMLConfig(t *testing.T) {
	t.Parallel()
	raw := `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
	`

	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)

	// Enabled by default
	assert.True(t, cfg.IsEnabled())

	raw = `
Enabled = true
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
	`

	cfg, err = NewDecodedTOMLConfig(raw)
	require.NoError(t, err)

	// Explicitly enabled
	assert.NotNil(t, cfg.Enabled)
	assert.True(t, cfg.IsEnabled())

	raw = `
Enabled = false
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
	`

	_, err = NewDecodedTOMLConfig(raw)
	require.ErrorContains(t, err, "config is disabled")
}

// TestTOMLConfig_CustomValues verifies that fully-specified custom TOML values
// survive the decode → applyDefaults → validate pipeline.
func TestTOMLConfig_CustomValues(t *testing.T) {
	t.Parallel()

	t.Run("LogPoller", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[LogPoller]
EventPollingInterval = "15s"
TxPollingInterval = "20s"
EventBatchSize = 50
TxBatchSize = 75
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)

		assert.Equal(t, 15*time.Second, cfg.LogPoller.EventPollingInterval.Duration())
		assert.Equal(t, 20*time.Second, cfg.LogPoller.TxPollingInterval.Duration())
		assert.Equal(t, uint64(50), *cfg.LogPoller.EventBatchSize)
		assert.Equal(t, uint64(75), *cfg.LogPoller.TxBatchSize)
	})

	t.Run("TransactionManager", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[TransactionManager]
GasLimitOverhead = 34
DefaultMaxGasAmount = 300000
BroadcastChanSize = 200
ConfirmPollSecs = 3
MaxSimulateAttempts = 10
MaxSubmitRetryAttempts = 15
SubmitDelayDuration = 5
TxExpirationSecs = 20
MaxTxRetryAttempts = 8
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)

		assert.Equal(t, uint64(34), *cfg.TransactionManager.GasLimitOverhead)
		assert.Equal(t, uint64(300000), *cfg.TransactionManager.DefaultMaxGasAmount)
		assert.Equal(t, uint(200), *cfg.TransactionManager.BroadcastChanSize)
		assert.Equal(t, uint(3), *cfg.TransactionManager.ConfirmPollSecs)
		assert.Equal(t, uint(10), *cfg.TransactionManager.MaxSimulateAttempts)
		assert.Equal(t, uint(15), *cfg.TransactionManager.MaxSubmitRetryAttempts)
		assert.Equal(t, uint(5), *cfg.TransactionManager.SubmitDelayDuration)
		assert.Equal(t, uint64(20), *cfg.TransactionManager.TxExpirationSecs)
		assert.Equal(t, uint64(8), *cfg.TransactionManager.MaxTxRetryAttempts)
	})

	t.Run("WriteTargetCap", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[WriteTargetCap]
Tag = "custom-tag"
ConfirmerPollPeriod = "5s"
ConfirmerTimeout = "30s"
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		require.NotNil(t, cfg.WriteTargetCap)
		assert.Equal(t, "custom-tag", *cfg.WriteTargetCap.Tag)
		assert.Equal(t, 5*time.Second, cfg.WriteTargetCap.ConfirmerPollPeriod.Duration())
		assert.Equal(t, 30*time.Second, cfg.WriteTargetCap.ConfirmerTimeout.Duration())
	})

	t.Run("BalanceMonitor", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[BalanceMonitor]
BalancePollPeriod = "30s"
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		require.NotNil(t, cfg.BalanceMonitor)
		assert.Equal(t, 30*time.Second, cfg.BalanceMonitor.BalancePollPeriod.Duration())
	})
}

// Regression guard: global DefaultConfigSet must never be mutated by config resolution
func TestNoGlobalMutation(t *testing.T) {
	t.Parallel()

	originalTM := DefaultConfigSet.TransactionManager
	originalLP := DefaultConfigSet.LogPoller
	originalBM := DefaultConfigSet.BalanceMonitor
	originalWT := DefaultConfigSet.WriteTargetCap

	cfg, err := NewDecodedTOMLConfig(baseTOML + `
[TransactionManager]
BroadcastChanSize = 999
`)
	require.NoError(t, err)

	// Mutate through the returned pointer
	*cfg.TransactionManager.BroadcastChanSize = 12345

	assert.Equal(t, originalTM, DefaultConfigSet.TransactionManager, "TransactionManager defaults must not be mutated")
	assert.Equal(t, originalLP, DefaultConfigSet.LogPoller, "LogPoller defaults must not be mutated")
	assert.Equal(t, originalBM, DefaultConfigSet.BalanceMonitor, "BalanceMonitor defaults must not be mutated")
	assert.Equal(t, originalWT, DefaultConfigSet.WriteTargetCap, "WriteTargetCap defaults must not be mutated")
}

