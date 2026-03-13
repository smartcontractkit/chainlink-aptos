package txm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve_AllDefaults(t *testing.T) {
	t.Parallel()

	cfg := Config{}
	cfg.Resolve()

	assert.Equal(t, DefaultConfigSet.BroadcastChanSize, cfg.BroadcastChanSize)
	assert.Equal(t, DefaultConfigSet.ConfirmPollSecs, cfg.ConfirmPollSecs)
	assert.Equal(t, DefaultConfigSet.DefaultMaxGasAmount, cfg.DefaultMaxGasAmount)
	assert.Equal(t, DefaultConfigSet.GasLimitOverhead, cfg.GasLimitOverhead)
	assert.Equal(t, DefaultConfigSet.MaxSimulateAttempts, cfg.MaxSimulateAttempts)
	assert.Equal(t, DefaultConfigSet.MaxSubmitRetryAttempts, cfg.MaxSubmitRetryAttempts)
	assert.Equal(t, DefaultConfigSet.SubmitDelayDuration, cfg.SubmitDelayDuration)
	assert.Equal(t, DefaultConfigSet.TxExpirationSecs, cfg.TxExpirationSecs)
	assert.Equal(t, DefaultConfigSet.MaxTxRetryAttempts, cfg.MaxTxRetryAttempts)
	assert.Equal(t, DefaultConfigSet.PruneIntervalSecs, cfg.PruneIntervalSecs)
	assert.Equal(t, DefaultConfigSet.PruneTxExpirationSecs, cfg.PruneTxExpirationSecs)
}


