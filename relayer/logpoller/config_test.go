package logpoller

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve_AllDefaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	cfg.Resolve()

	assert.Equal(t, DefaultConfigSet.EventPollingInterval.Duration(), cfg.EventPollingInterval.Duration())
	assert.Equal(t, DefaultConfigSet.TxPollingInterval.Duration(), cfg.TxPollingInterval.Duration())
	assert.Equal(t, DefaultConfigSet.PollTimeout.Duration(), cfg.PollTimeout.Duration())
	assert.Equal(t, DefaultConfigSet.EventBatchSize, cfg.EventBatchSize)
	assert.Equal(t, DefaultConfigSet.TxBatchSize, cfg.TxBatchSize)
	assert.Equal(t, DefaultConfigSet.TXPollerDisabled, cfg.TXPollerDisabled)
}


