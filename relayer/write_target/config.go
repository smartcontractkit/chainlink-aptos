package write_target

import (
	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

// Config defines the write target component configuration.
type Config struct {
	ConfirmerPollPeriod config.Duration
	ConfirmerTimeout    config.Duration
}
