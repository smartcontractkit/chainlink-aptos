package aptosservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResolve_AllDefaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	cfg.Resolve()

	assert.Equal(t, DefaultConfigSet.SubmitPollTimeout, cfg.SubmitPollTimeout)
	assert.Equal(t, DefaultConfigSet.SimulateTx, cfg.SimulateTx)
}

func TestResolve_PartialOverride(t *testing.T) {
	t.Parallel()

	cfg := Config{
		SimulateTx: ptr(false),
	}
	cfg.Resolve()

	assert.Equal(t, false, *cfg.SimulateTx)
	assert.Equal(t, 10*time.Second, cfg.SubmitPollTimeout.Duration())
}

func TestResolve_ExplicitFalse(t *testing.T) {
	t.Parallel()

	cfg := Config{
		SimulateTx: ptr(false),
	}
	cfg.Resolve()

	assert.Equal(t, false, *cfg.SimulateTx,
		"explicit false must not be overwritten by default true")
	assert.Equal(t, DefaultConfigSet.SubmitPollTimeout, cfg.SubmitPollTimeout)
}
