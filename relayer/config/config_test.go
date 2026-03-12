package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target"
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
	// This is a core expectation of the API contract.
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

func TestTOMLConfig_LogPoller(t *testing.T) {
	t.Parallel()

	// Test with default config
	raw := `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
    `

	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)

	// Check that LogPoller config has defaults
	assert.NotNil(t, cfg.LogPoller)
	assert.Equal(t, 12*time.Second, cfg.LogPoller.EventPollingInterval.Duration())
	assert.Equal(t, uint64(100), *cfg.LogPoller.EventBatchSize)

	// Test with custom config
	raw = `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"

[LogPoller]
EventPollingInterval = "15s"
TxPollingInterval = "20s"
EventBatchSize = 50
TxBatchSize = 75
    `

	cfg, err = NewDecodedTOMLConfig(raw)
	require.NoError(t, err)

	assert.Equal(t, 15*time.Second, cfg.LogPoller.EventPollingInterval.Duration())
	assert.Equal(t, 20*time.Second, cfg.LogPoller.TxPollingInterval.Duration())
	assert.Equal(t, uint64(50), *cfg.LogPoller.EventBatchSize)
	assert.Equal(t, uint64(75), *cfg.LogPoller.TxBatchSize)
}

func TestTOMLConfig_TxManager(t *testing.T) {
	t.Parallel()

	// Test with default config
	raw := `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"
    `

	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)

	// Check that TxManager config has defaults
	assert.NotNil(t, cfg.TransactionManager)
	assert.Equal(t, uint64(0), *cfg.TransactionManager.GasLimitOverhead)
	assert.Equal(t, uint64(200000), *cfg.TransactionManager.DefaultMaxGasAmount)
	assert.Equal(t, uint(100), *cfg.TransactionManager.BroadcastChanSize)
	assert.Equal(t, uint(2), *cfg.TransactionManager.ConfirmPollSecs)

	// Test with custom config
	raw = `
ChainID = "2"
[[Nodes]]
Name = "node-1"
URL = "http://node-1"

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

	cfg, err = NewDecodedTOMLConfig(raw)
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
}

// TEST-02: Partial TransactionManager -- user field preserved, remaining 10 fields merged from defaults
func TestSetDefaults_PartialTransactionManager(t *testing.T) {
	t.Parallel()

	raw := baseTOML + `
[TransactionManager]
BroadcastChanSize = 50
`
	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)
	require.NotNil(t, cfg.TransactionManager)

	// User-specified field preserved
	assert.Equal(t, uint(50), *cfg.TransactionManager.BroadcastChanSize)

	// All 10 remaining fields merged from txm.DefaultConfigSet
	assert.Equal(t, txm.DefaultConfigSet.ConfirmPollSecs, cfg.TransactionManager.ConfirmPollSecs)
	assert.Equal(t, txm.DefaultConfigSet.DefaultMaxGasAmount, cfg.TransactionManager.DefaultMaxGasAmount)
	assert.Equal(t, txm.DefaultConfigSet.GasLimitOverhead, cfg.TransactionManager.GasLimitOverhead)
	assert.Equal(t, txm.DefaultConfigSet.MaxSimulateAttempts, cfg.TransactionManager.MaxSimulateAttempts)
	assert.Equal(t, txm.DefaultConfigSet.MaxSubmitRetryAttempts, cfg.TransactionManager.MaxSubmitRetryAttempts)
	assert.Equal(t, txm.DefaultConfigSet.SubmitDelayDuration, cfg.TransactionManager.SubmitDelayDuration)
	assert.Equal(t, txm.DefaultConfigSet.TxExpirationSecs, cfg.TransactionManager.TxExpirationSecs)
	assert.Equal(t, txm.DefaultConfigSet.MaxTxRetryAttempts, cfg.TransactionManager.MaxTxRetryAttempts)
	assert.Equal(t, txm.DefaultConfigSet.PruneIntervalSecs, cfg.TransactionManager.PruneIntervalSecs)
	assert.Equal(t, txm.DefaultConfigSet.PruneTxExpirationSecs, cfg.TransactionManager.PruneTxExpirationSecs)
}

// TEST-03: Partial LogPoller -- user field preserved, remaining 5 fields merged from defaults
func TestSetDefaults_PartialLogPoller(t *testing.T) {
	t.Parallel()

	raw := baseTOML + `
[LogPoller]
EventBatchSize = 50
`
	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)
	require.NotNil(t, cfg.LogPoller)

	// User-specified field preserved
	assert.Equal(t, uint64(50), *cfg.LogPoller.EventBatchSize)

	// All 5 remaining fields merged from logpoller.DefaultConfigSet
	assert.Equal(t, logpoller.DefaultConfigSet.EventPollingInterval.Duration(), cfg.LogPoller.EventPollingInterval.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.TxPollingInterval.Duration(), cfg.LogPoller.TxPollingInterval.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.PollTimeout.Duration(), cfg.LogPoller.PollTimeout.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.TxBatchSize, cfg.LogPoller.TxBatchSize)
	assert.Equal(t, logpoller.DefaultConfigSet.TXPollerDisabled, cfg.LogPoller.TXPollerDisabled)
}

// TEST-04: Partial BalanceMonitor -- custom value preserved; empty section gets defaults
func TestSetDefaults_PartialBalanceMonitor(t *testing.T) {
	t.Parallel()

	t.Run("custom value preserved", func(t *testing.T) {
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

	t.Run("empty section gets defaults", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[BalanceMonitor]
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		require.NotNil(t, cfg.BalanceMonitor)
		assert.Equal(t, DefaultConfigSet.BalanceMonitor.BalancePollPeriod.Duration(), cfg.BalanceMonitor.BalancePollPeriod.Duration())
	})
}

// TEST-05: Partial WriteTargetCap -- user field preserved, remaining 2 fields merged from defaults
func TestSetDefaults_PartialWriteTargetCap(t *testing.T) {
	t.Parallel()

	raw := baseTOML + `
[WriteTargetCap]
Tag = "custom"
`
	cfg, err := NewDecodedTOMLConfig(raw)
	require.NoError(t, err)
	require.NotNil(t, cfg.WriteTargetCap)

	// User-specified field preserved
	assert.Equal(t, "custom", *cfg.WriteTargetCap.Tag)

	// Remaining 2 fields merged from write_target.DefaultConfigSet
	assert.Equal(t, write_target.DefaultConfigSet.ConfirmerPollPeriod.Duration(), cfg.WriteTargetCap.ConfirmerPollPeriod.Duration())
	assert.Equal(t, write_target.DefaultConfigSet.ConfirmerTimeout.Duration(), cfg.WriteTargetCap.ConfirmerTimeout.Duration())
}

// TEST-06: Edge cases -- zero-valued defaults are correctly applied (not treated as "unset")
func TestSetDefaults_EdgeCases_ZeroDefaults(t *testing.T) {
	t.Parallel()

	t.Run("GasLimitOverhead remains 0 with partial TXM config", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[TransactionManager]
BroadcastChanSize = 50
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), *cfg.TransactionManager.GasLimitOverhead,
			"GasLimitOverhead should be 0 -- the default IS zero")
	})

	t.Run("TXPollerDisabled remains false with partial LogPoller config", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[LogPoller]
EventBatchSize = 50
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, false, *cfg.LogPoller.TXPollerDisabled,
			"TXPollerDisabled should be false -- the default IS false")
	})
}

// TEST-07: Absent sections -- nil pointers produce complete defaults for all 4 sections
func TestSetDefaults_AbsentSections(t *testing.T) {
	t.Parallel()

	// No config section headers at all -- just base TOML
	cfg, err := NewDecodedTOMLConfig(baseTOML)
	require.NoError(t, err)

	// All 4 section pointers must be non-nil after applyDefaults
	require.NotNil(t, cfg.TransactionManager)
	require.NotNil(t, cfg.LogPoller)
	require.NotNil(t, cfg.BalanceMonitor)
	require.NotNil(t, cfg.WriteTargetCap)

	// TransactionManager: all 11 fields match txm.DefaultConfigSet
	assert.Equal(t, txm.DefaultConfigSet.BroadcastChanSize, cfg.TransactionManager.BroadcastChanSize)
	assert.Equal(t, txm.DefaultConfigSet.ConfirmPollSecs, cfg.TransactionManager.ConfirmPollSecs)
	assert.Equal(t, txm.DefaultConfigSet.DefaultMaxGasAmount, cfg.TransactionManager.DefaultMaxGasAmount)
	assert.Equal(t, txm.DefaultConfigSet.GasLimitOverhead, cfg.TransactionManager.GasLimitOverhead)
	assert.Equal(t, txm.DefaultConfigSet.MaxSimulateAttempts, cfg.TransactionManager.MaxSimulateAttempts)
	assert.Equal(t, txm.DefaultConfigSet.MaxSubmitRetryAttempts, cfg.TransactionManager.MaxSubmitRetryAttempts)
	assert.Equal(t, txm.DefaultConfigSet.SubmitDelayDuration, cfg.TransactionManager.SubmitDelayDuration)
	assert.Equal(t, txm.DefaultConfigSet.TxExpirationSecs, cfg.TransactionManager.TxExpirationSecs)
	assert.Equal(t, txm.DefaultConfigSet.MaxTxRetryAttempts, cfg.TransactionManager.MaxTxRetryAttempts)
	assert.Equal(t, txm.DefaultConfigSet.PruneIntervalSecs, cfg.TransactionManager.PruneIntervalSecs)
	assert.Equal(t, txm.DefaultConfigSet.PruneTxExpirationSecs, cfg.TransactionManager.PruneTxExpirationSecs)

	// LogPoller: all 6 fields match logpoller.DefaultConfigSet
	assert.Equal(t, logpoller.DefaultConfigSet.EventPollingInterval.Duration(), cfg.LogPoller.EventPollingInterval.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.TxPollingInterval.Duration(), cfg.LogPoller.TxPollingInterval.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.PollTimeout.Duration(), cfg.LogPoller.PollTimeout.Duration())
	assert.Equal(t, logpoller.DefaultConfigSet.EventBatchSize, cfg.LogPoller.EventBatchSize)
	assert.Equal(t, logpoller.DefaultConfigSet.TxBatchSize, cfg.LogPoller.TxBatchSize)
	assert.Equal(t, logpoller.DefaultConfigSet.TXPollerDisabled, cfg.LogPoller.TXPollerDisabled)

	// BalanceMonitor: 1 field matches DefaultConfigSet.BalanceMonitor
	assert.Equal(t, DefaultConfigSet.BalanceMonitor.BalancePollPeriod.Duration(), cfg.BalanceMonitor.BalancePollPeriod.Duration())

	// WriteTargetCap: all 3 fields match write_target.DefaultConfigSet
	assert.Equal(t, write_target.DefaultConfigSet.Tag, cfg.WriteTargetCap.Tag)
	assert.Equal(t, write_target.DefaultConfigSet.ConfirmerPollPeriod.Duration(), cfg.WriteTargetCap.ConfirmerPollPeriod.Duration())
	assert.Equal(t, write_target.DefaultConfigSet.ConfirmerTimeout.Duration(), cfg.WriteTargetCap.ConfirmerTimeout.Duration())
}

// TEST-08: Fully specified sections retain all user-provided values
func TestSetDefaults_FullySpecified(t *testing.T) {
	t.Parallel()

	t.Run("BalanceMonitor retains all values", func(t *testing.T) {
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

	t.Run("WriteTargetCap retains all values", func(t *testing.T) {
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
}

// Regression guard: global DefaultConfigSet must never be mutated by config resolution
func TestNoGlobalMutation(t *testing.T) {
	t.Parallel()

	// Snapshot all 4 DefaultConfigSet sub-structs before test
	originalTM := DefaultConfigSet.TransactionManager
	originalLP := DefaultConfigSet.LogPoller
	originalBM := DefaultConfigSet.BalanceMonitor
	originalWT := DefaultConfigSet.WriteTargetCap

	// Create config with a partial section
	cfg, err := NewDecodedTOMLConfig(baseTOML + `
[TransactionManager]
BroadcastChanSize = 999
`)
	require.NoError(t, err)

	// Mutate through the returned pointer
	*cfg.TransactionManager.BroadcastChanSize = 12345

	// Assert all 4 DefaultConfigSet sub-structs are unchanged
	assert.Equal(t, originalTM, DefaultConfigSet.TransactionManager, "TransactionManager defaults must not be mutated")
	assert.Equal(t, originalLP, DefaultConfigSet.LogPoller, "LogPoller defaults must not be mutated")
	assert.Equal(t, originalBM, DefaultConfigSet.BalanceMonitor, "BalanceMonitor defaults must not be mutated")
	assert.Equal(t, originalWT, DefaultConfigSet.WriteTargetCap, "WriteTargetCap defaults must not be mutated")
}

// Explicit zero overrides: user can set a field to 0/false and it is NOT
// replaced by the default. This is the key improvement of the pointer-based
// TOML deserialization approach.
func TestExplicitZeroOverride(t *testing.T) {
	t.Parallel()

	t.Run("TransactionManager explicit zero overrides default", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[TransactionManager]
DefaultMaxGasAmount = 0
MaxSimulateAttempts = 0
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), *cfg.TransactionManager.DefaultMaxGasAmount,
			"explicit 0 must override default of 200000")
		assert.Equal(t, uint(0), *cfg.TransactionManager.MaxSimulateAttempts,
			"explicit 0 must override default of 5")
		// Non-specified fields still get defaults
		assert.Equal(t, txm.DefaultConfigSet.BroadcastChanSize, cfg.TransactionManager.BroadcastChanSize)
	})

	t.Run("LogPoller explicit false overrides default", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[LogPoller]
EventBatchSize = 0
TXPollerDisabled = false
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, uint64(0), *cfg.LogPoller.EventBatchSize,
			"explicit 0 must override default of 100")
		assert.Equal(t, false, *cfg.LogPoller.TXPollerDisabled,
			"explicit false must be preserved")
		// Non-specified fields still get defaults
		assert.Equal(t, logpoller.DefaultConfigSet.EventPollingInterval.Duration(),
			cfg.LogPoller.EventPollingInterval.Duration())
	})

	t.Run("WriteTargetCap explicit empty string", func(t *testing.T) {
		t.Parallel()

		raw := baseTOML + `
[WriteTargetCap]
Tag = ""
`
		cfg, err := NewDecodedTOMLConfig(raw)
		require.NoError(t, err)
		assert.Equal(t, "", *cfg.WriteTargetCap.Tag,
			"explicit empty string must be preserved")
		// Non-specified fields still get defaults
		assert.Equal(t, write_target.DefaultConfigSet.ConfirmerPollPeriod.Duration(),
			cfg.WriteTargetCap.ConfirmerPollPeriod.Duration())
	})
}
