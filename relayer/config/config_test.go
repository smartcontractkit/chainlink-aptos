package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
	assert.Equal(t, uint64(100), cfg.LogPoller.EventBatchSize)

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
	assert.Equal(t, uint64(50), cfg.LogPoller.EventBatchSize)
	assert.Equal(t, uint64(75), cfg.LogPoller.TxBatchSize)
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
	assert.Equal(t, uint64(0), cfg.TransactionManager.GasLimitOverhead)
	assert.Equal(t, uint64(200000), cfg.TransactionManager.DefaultMaxGasAmount)
	assert.Equal(t, uint(100), cfg.TransactionManager.BroadcastChanSize)
	assert.Equal(t, uint(2), cfg.TransactionManager.ConfirmPollSecs)

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

	assert.Equal(t, uint64(34), cfg.TransactionManager.GasLimitOverhead)
	assert.Equal(t, uint64(300000), cfg.TransactionManager.DefaultMaxGasAmount)
	assert.Equal(t, uint(200), cfg.TransactionManager.BroadcastChanSize)
	assert.Equal(t, uint(3), cfg.TransactionManager.ConfirmPollSecs)
	assert.Equal(t, uint(10), cfg.TransactionManager.MaxSimulateAttempts)
	assert.Equal(t, uint(15), cfg.TransactionManager.MaxSubmitRetryAttempts)
	assert.Equal(t, uint(5), cfg.TransactionManager.SubmitDelayDuration)
	assert.Equal(t, uint64(20), cfg.TransactionManager.TxExpirationSecs)
	assert.Equal(t, uint64(8), cfg.TransactionManager.MaxTxRetryAttempts)
}
