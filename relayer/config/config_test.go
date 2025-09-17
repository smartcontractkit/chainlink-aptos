package config

import (
	_ "embed"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/config/configtest"
)

func TestTOMLConfig_IsEnabled(t *testing.T) {
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

func TestDefaults_fieldsNotNil(t *testing.T) {
	configtest.AssertFieldsNotNil(t, Defaults())
}

func TestDocsTOMLComplete(t *testing.T) {
	configtest.AssertDocsTOMLComplete[TOMLConfig](t, docsTOML)
}

//go:embed testdata/config-full.toml
var fullTOML string

func TestTOMLConfig_FullMarshal(t *testing.T) {
	full := TOMLConfig{
		Enabled:         ptr(true),
		ChainID:         ptr("fake-chain"),
		NetworkName:     ptr("net"),
		NetworkNameFull: ptr("network"),
		Chain: Chain{
			TransactionManager: &TxmConfig{
				BroadcastChanSize:      1,
				ConfirmPollSecs:        ptr[uint](1),
				ConfirmPoll:            config.MustNewDuration(time.Second),
				DefaultMaxGasAmount:    2,
				MaxSimulateAttempts:    3,
				MaxSubmitRetryAttempts: 4,
				SubmitDelayDuration:    config.MustNewDuration(time.Minute),
				TxExpirationSecs:       ptr[uint64](360),
				TxExpiration:           config.MustNewDuration(time.Hour),
				MaxTxRetryAttempts:     5,
				PruneIntervalSecs:      ptr[uint64](100),
				PruneInterval:          config.MustNewDuration(time.Millisecond),
				PruneTxExpirationSecs:  ptr[uint64](42),
				PruneTxExpiration:      config.MustNewDuration(time.Microsecond),
			},
			LogPoller: &logpoller.Config{
				EventPollingInterval: config.MustNewDuration(12 * time.Second),
				TxPollingInterval:    config.MustNewDuration(12 * time.Second),
				PollTimeout:          config.MustNewDuration(10 * time.Second),
				EventBatchSize:       ptr[uint64](100),
				TxBatchSize:          ptr[uint64](100),
				TXPollerDisabled:     ptr(true),
			},
			BalanceMonitor: &monitor.GenericBalanceConfig{
				BalancePollPeriod: config.MustNewDuration(time.Nanosecond),
			},
			WriteTargetCap: &write_target.Config{
				ConfirmerPollPeriod: config.MustNewDuration(2 * time.Hour),
				ConfirmerTimeout:    config.MustNewDuration(2 * time.Minute),
			},
			Workflow: &WorkflowConfig{
				ForwarderAddress: "foo",
				PublicKey:        "bar",
			},
		},
		Nodes: Nodes{
			{Name: ptr("baz"), URL: config.MustParseURL("https://example.com")},
		},
	}
	configtest.AssertFullMarshal(t, full, fullTOML)
}

func ptr[T any](v T) *T { return &v }
