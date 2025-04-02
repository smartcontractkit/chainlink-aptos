package write_target

import (
	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

// Config defines the write target component configuration.
type Config struct {
	Tag                 *string // allows modifying WT ID e.g. write_aptos-testnet:{{.Tag}}@1.0.3
	ConfirmerPollPeriod *config.Duration
	ConfirmerTimeout    *config.Duration
}

