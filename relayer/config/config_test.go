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
