package logpoller

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

// Config holds configuration for the LogPoller
type Config struct {
	// EventPollingInterval is the interval at which events are polled
	EventPollingInterval config.Duration

	// TxPollingInterval is the interval at which transactions are polled
	TxPollingInterval config.Duration

	// PollTimeout is the maximum time a single polling operation can take
	PollTimeout config.Duration

	// EventBatchSize is the maximum number of events to fetch in a single request
	EventBatchSize uint64

	// TxBatchSize is the maximum number of transactions to fetch in a single request
	TxBatchSize uint64
}

// DefaultConfigSet is the default configuration for LogPoller
var DefaultConfigSet = Config{
	EventPollingInterval: *config.MustNewDuration(12 * time.Second),
	TxPollingInterval:    *config.MustNewDuration(12 * time.Second),
	PollTimeout:          *config.MustNewDuration(10 * time.Second),
	EventBatchSize:       100,
	TxBatchSize:          100,
}
