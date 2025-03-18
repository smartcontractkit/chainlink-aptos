package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTOMLConfig(t *testing.T) {
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

	cfg, err = NewDecodedTOMLConfig(raw)
	require.ErrorContains(t, err, "config is disabled")
}
