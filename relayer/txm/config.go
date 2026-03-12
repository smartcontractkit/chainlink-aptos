package txm

func ptr[T any](v T) *T { return &v }

// TODO: these should be duration, not numbers
// Config defines the transaction manager configuration.
// Pointer fields are used for TOML deserialization — nil means "not set by user".
// After calling Resolve(), all fields are guaranteed non-nil.
type Config struct {
	BroadcastChanSize *uint `toml:"BroadcastChanSize"`
	ConfirmPollSecs   *uint `toml:"ConfirmPollSecs"`

	DefaultMaxGasAmount *uint64 `toml:"DefaultMaxGasAmount"`
	GasLimitOverhead    *uint64 `toml:"GasLimitOverhead"`

	MaxSimulateAttempts    *uint   `toml:"MaxSimulateAttempts"`
	MaxSubmitRetryAttempts *uint   `toml:"MaxSubmitRetryAttempts"`
	SubmitDelayDuration    *uint   `toml:"SubmitDelayDuration"`
	TxExpirationSecs       *uint64 `toml:"TxExpirationSecs"`
	MaxTxRetryAttempts     *uint64 `toml:"MaxTxRetryAttempts"`
	PruneIntervalSecs      *uint64 `toml:"PruneIntervalSecs"`
	PruneTxExpirationSecs  *uint64 `toml:"PruneTxExpirationSecs"`
}

// DefaultConfigSet is the default configuration for the TransactionManager
var DefaultConfigSet = Config{
	BroadcastChanSize: ptr(uint(100)),
	ConfirmPollSecs:   ptr(uint(2)),

	// https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21
	DefaultMaxGasAmount: ptr(uint64(200000)),
	GasLimitOverhead:    ptr(uint64(0)),

	MaxSimulateAttempts:    ptr(uint(5)),
	MaxSubmitRetryAttempts: ptr(uint(10)),
	SubmitDelayDuration:    ptr(uint(3)),            // seconds
	TxExpirationSecs:       ptr(uint64(10)),         // seconds
	MaxTxRetryAttempts:     ptr(uint64(5)),
	PruneIntervalSecs:      ptr(uint64(60 * 60 * 4)), // 4 hours
	PruneTxExpirationSecs:  ptr(uint64(60 * 60 * 2)), // 2 hours
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.BroadcastChanSize == nil {
		c.BroadcastChanSize = ptr(*DefaultConfigSet.BroadcastChanSize)
	}
	if c.ConfirmPollSecs == nil {
		c.ConfirmPollSecs = ptr(*DefaultConfigSet.ConfirmPollSecs)
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
	if c.SubmitDelayDuration == nil {
		c.SubmitDelayDuration = ptr(*DefaultConfigSet.SubmitDelayDuration)
	}
	if c.TxExpirationSecs == nil {
		c.TxExpirationSecs = ptr(*DefaultConfigSet.TxExpirationSecs)
	}
	if c.MaxTxRetryAttempts == nil {
		c.MaxTxRetryAttempts = ptr(*DefaultConfigSet.MaxTxRetryAttempts)
	}
	if c.PruneIntervalSecs == nil {
		c.PruneIntervalSecs = ptr(*DefaultConfigSet.PruneIntervalSecs)
	}
	if c.PruneTxExpirationSecs == nil {
		c.PruneTxExpirationSecs = ptr(*DefaultConfigSet.PruneTxExpirationSecs)
	}
}
