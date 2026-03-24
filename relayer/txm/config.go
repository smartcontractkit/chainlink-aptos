package txm

import (
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
)

func ptr[T any](v T) *T { return &v }

// Config defines the transaction manager configuration.
// Pointer fields are used for TOML deserialization — nil means "not set by user".
// After calling Resolve(), all fields are guaranteed non-nil.
type Config struct {
	BroadcastChanSize *uint `toml:"BroadcastChanSize"`

	ConfirmPollInterval *config.Duration `toml:"ConfirmPollInterval"`

	DefaultMaxGasAmount *uint64 `toml:"DefaultMaxGasAmount"`
	GasLimitOverhead    *uint64 `toml:"GasLimitOverhead"`

	MaxSimulateAttempts    *uint            `toml:"MaxSimulateAttempts"`
	MaxSubmitRetryAttempts *uint            `toml:"MaxSubmitRetryAttempts"`
	SubmitRetryDelay       *config.Duration `toml:"SubmitRetryDelay"`
	TxExpirationTimeout    *config.Duration `toml:"TxExpirationTimeout"`
	MaxTxRetryAttempts     *uint64          `toml:"MaxTxRetryAttempts"`
	PruneInterval          *config.Duration `toml:"PruneInterval"`
	PruneTxExpiration      *config.Duration `toml:"PruneTxExpiration"`
}

// DefaultConfigSet is the default configuration for the TransactionManager
var DefaultConfigSet = Config{
	BroadcastChanSize:   ptr(uint(100)),
	ConfirmPollInterval: config.MustNewDuration(2 * time.Second),

	// https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21
	DefaultMaxGasAmount: ptr(uint64(200000)),
	GasLimitOverhead:    ptr(uint64(0)),

	MaxSimulateAttempts:    ptr(uint(5)),
	MaxSubmitRetryAttempts: ptr(uint(10)),
	SubmitRetryDelay:       config.MustNewDuration(3 * time.Second),
	TxExpirationTimeout:    config.MustNewDuration(10 * time.Second),
	MaxTxRetryAttempts:     ptr(uint64(5)),
	PruneInterval:          config.MustNewDuration(4 * time.Hour),
	PruneTxExpiration:      config.MustNewDuration(2 * time.Hour),
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.BroadcastChanSize == nil {
		c.BroadcastChanSize = ptr(*DefaultConfigSet.BroadcastChanSize)
	}
	if c.ConfirmPollInterval == nil {
		v := *DefaultConfigSet.ConfirmPollInterval
		c.ConfirmPollInterval = &v
	}
	if c.DefaultMaxGasAmount == nil {
		c.DefaultMaxGasAmount = ptr(*DefaultConfigSet.DefaultMaxGasAmount)
	}
	if c.GasLimitOverhead == nil {
		c.GasLimitOverhead = ptr(*DefaultConfigSet.GasLimitOverhead)
	}
	if c.MaxSimulateAttempts == nil {
		c.MaxSimulateAttempts = ptr(*DefaultConfigSet.MaxSimulateAttempts)
	}
	if c.MaxSubmitRetryAttempts == nil {
		c.MaxSubmitRetryAttempts = ptr(*DefaultConfigSet.MaxSubmitRetryAttempts)
	}
	if c.SubmitRetryDelay == nil {
		v := *DefaultConfigSet.SubmitRetryDelay
		c.SubmitRetryDelay = &v
	}
	if c.TxExpirationTimeout == nil {
		v := *DefaultConfigSet.TxExpirationTimeout
		c.TxExpirationTimeout = &v
	}
	if c.MaxTxRetryAttempts == nil {
		c.MaxTxRetryAttempts = ptr(*DefaultConfigSet.MaxTxRetryAttempts)
	}
	if c.PruneInterval == nil {
		v := *DefaultConfigSet.PruneInterval
		c.PruneInterval = &v
	}
	if c.PruneTxExpiration == nil {
		v := *DefaultConfigSet.PruneTxExpiration
		c.PruneTxExpiration = &v
	}
}
