package aptosservice

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

func ptr[T any](v T) *T { return &v }

// Config defines the Aptos service configuration.
// Pointer fields are used for TOML deserialization — nil means "not set by user".
// After calling Resolve(), all fields are guaranteed non-nil.
type Config struct {
	SubmitPollTimeout *config.Duration `toml:"SubmitPollTimeout"`
	SimulateTx        *bool            `toml:"SimulateTx"`
}

// DefaultConfigSet is the default configuration for the Aptos service.
var DefaultConfigSet = Config{
	SubmitPollTimeout: config.MustNewDuration(10 * time.Second),
	SimulateTx:        ptr(true),
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.SubmitPollTimeout == nil {
		v := *DefaultConfigSet.SubmitPollTimeout
		c.SubmitPollTimeout = &v
	}
	if c.SimulateTx == nil {
		c.SimulateTx = ptr(*DefaultConfigSet.SimulateTx)
	}
}
