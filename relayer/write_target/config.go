package write_target

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

func ptr[T any](v T) *T { return &v }

// Config defines the write target component configuration.
// Pointer fields are used for TOML deserialization — nil means "not set by user".
// After calling Resolve(), all fields are guaranteed non-nil.
type Config struct {
	Tag                 *string          `toml:"Tag"` // allows modifying WT ID e.g. write_aptos-testnet:{{.Tag}}@1.0.3
	ConfirmerPollPeriod *config.Duration `toml:"ConfirmerPollPeriod"`
	ConfirmerTimeout    *config.Duration `toml:"ConfirmerTimeout"`
}

// DefaultConfigSet is the default configuration for the write target component.
var DefaultConfigSet = Config{
	Tag:                 ptr(""),
	ConfirmerPollPeriod: config.MustNewDuration(1 * time.Second),
	ConfirmerTimeout:    config.MustNewDuration(10 * time.Second),
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.Tag == nil {
		c.Tag = ptr(*DefaultConfigSet.Tag)
	}
	if c.ConfirmerPollPeriod == nil {
		v := *DefaultConfigSet.ConfirmerPollPeriod
		c.ConfirmerPollPeriod = &v
	}
	if c.ConfirmerTimeout == nil {
		v := *DefaultConfigSet.ConfirmerTimeout
		c.ConfirmerTimeout = &v
	}
}
