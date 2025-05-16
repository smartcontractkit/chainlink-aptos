package write_target

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

// Config defines the write target component configuration.
type Config struct {
	Tag                 string // allows modifying WT ID e.g. write_aptos-testnet:{{.Tag}}@1.0.3
	ConfirmerPollPeriod config.Duration
	ConfirmerTimeout    config.Duration
}

// DefaultConfigSet is the default configuration for the write target component.
var DefaultConfigSet = Config{
	ConfirmerPollPeriod: *config.MustNewDuration(1 * time.Second),
	ConfirmerTimeout:    *config.MustNewDuration(10 * time.Second),
}
