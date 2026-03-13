package monitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve_AllDefaults(t *testing.T) {
	t.Parallel()

	cfg := GenericBalanceConfig{}
	cfg.Resolve()

	assert.Equal(t, DefaultBalanceConfig.BalancePollPeriod.Duration(), cfg.BalancePollPeriod.Duration())
}
