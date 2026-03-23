package write_target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve_AllDefaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	cfg.Resolve()

	assert.Equal(t, DefaultConfigSet.Tag, cfg.Tag)
	assert.Equal(t, DefaultConfigSet.ConfirmerPollPeriod.Duration(), cfg.ConfirmerPollPeriod.Duration())
	assert.Equal(t, DefaultConfigSet.ConfirmerTimeout.Duration(), cfg.ConfirmerTimeout.Duration())
}

func TestResolve_PartialOverride(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Tag: ptr("custom"),
	}
	cfg.Resolve()

	assert.Equal(t, "custom", *cfg.Tag)
	assert.Equal(t, DefaultConfigSet.ConfirmerPollPeriod.Duration(), cfg.ConfirmerPollPeriod.Duration())
	assert.Equal(t, DefaultConfigSet.ConfirmerTimeout.Duration(), cfg.ConfirmerTimeout.Duration())
}

func TestResolve_ExplicitZero(t *testing.T) {
	t.Parallel()

	cfg := Config{
		Tag: ptr(""),
	}
	cfg.Resolve()

	assert.Equal(t, "", *cfg.Tag,
		"explicit empty string must be preserved")
	assert.Equal(t, DefaultConfigSet.ConfirmerPollPeriod.Duration(), cfg.ConfirmerPollPeriod.Duration())
	assert.Equal(t, DefaultConfigSet.ConfirmerTimeout.Duration(), cfg.ConfirmerTimeout.Duration())
}
