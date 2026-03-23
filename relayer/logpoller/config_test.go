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

func TestResolve_PartialOverride(t *testing.T) {
	t.Parallel()

	cfg := Config{
		EventBatchSize: ptr(uint64(50)),
	}
	cfg.Resolve()

	assert.Equal(t, uint64(50), *cfg.EventBatchSize)
	assert.Equal(t, DefaultConfigSet.EventPollingInterval.Duration(), cfg.EventPollingInterval.Duration())
	assert.Equal(t, DefaultConfigSet.TXPollerDisabled, cfg.TXPollerDisabled)
}

func TestResolve_ExplicitZero(t *testing.T) {
	t.Parallel()

	cfg := Config{
		EventBatchSize:   ptr(uint64(0)),
		TXPollerDisabled: ptr(false),
	}
	cfg.Resolve()

	assert.Equal(t, uint64(0), *cfg.EventBatchSize,
		"explicit 0 must not be overwritten by default of 100")
	assert.Equal(t, false, *cfg.TXPollerDisabled,
		"explicit false must be preserved")
	assert.Equal(t, DefaultConfigSet.EventPollingInterval.Duration(), cfg.EventPollingInterval.Duration())
}
