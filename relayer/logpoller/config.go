package logpoller

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

func ptr[T any](v T) *T { return &v }

// Config holds configuration for the LogPoller.
// Pointer fields are used for TOML deserialization — nil means "not set by user".
// After calling Resolve(), all fields are guaranteed non-nil.
type Config struct {
	// EventPollingInterval is the interval at which events are polled
	EventPollingInterval *config.Duration `toml:"EventPollingInterval"`

	// TxPollingInterval is the interval at which transactions are polled
	TxPollingInterval *config.Duration `toml:"TxPollingInterval"`

	// PollTimeout is the maximum time a single polling operation can take
	PollTimeout *config.Duration `toml:"PollTimeout"`

	// EventBatchSize is the maximum number of events to fetch in a single request
	EventBatchSize *uint64 `toml:"EventBatchSize"`

	// TxBatchSize is the maximum number of transactions to fetch in a single request
	TxBatchSize *uint64 `toml:"TxBatchSize"`

	// TXPollerDisabled if this is true, the TX poller will not run on log poller start
	TXPollerDisabled *bool `toml:"TXPollerDisabled"`
}

// DefaultConfigSet is the default configuration for LogPoller
var DefaultConfigSet = Config{
	EventPollingInterval: config.MustNewDuration(12 * time.Second),
	TxPollingInterval:    config.MustNewDuration(12 * time.Second),
	PollTimeout:          config.MustNewDuration(10 * time.Second),
	EventBatchSize:       ptr(uint64(100)),
	TxBatchSize:          ptr(uint64(100)),
	TXPollerDisabled:     ptr(false),
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.EventPollingInterval == nil {
		v := *DefaultConfigSet.EventPollingInterval
		c.EventPollingInterval = &v
	}
	if c.TxPollingInterval == nil {
		v := *DefaultConfigSet.TxPollingInterval
		c.TxPollingInterval = &v
	}
	if c.PollTimeout == nil {
		v := *DefaultConfigSet.PollTimeout
		c.PollTimeout = &v
	}
	if c.EventBatchSize == nil {
		c.EventBatchSize = ptr(*DefaultConfigSet.EventBatchSize)
	}
	if c.TxBatchSize == nil {
		c.TxBatchSize = ptr(*DefaultConfigSet.TxBatchSize)
	}
	if c.TXPollerDisabled == nil {
		c.TXPollerDisabled = ptr(*DefaultConfigSet.TXPollerDisabled)
	}
}
