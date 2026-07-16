package txm

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
	BroadcastChanSize: new(uint(100)),
	ConfirmPollSecs:   new(uint(2)),

	// https://github.com/aptos-labs/aptos-ts-sdk/blob/bc169793071185f638192efb1a90103db7ab4922/src/utils/const.ts#L27
	DefaultMaxGasAmount: new(uint64(2_000_000)),
	GasLimitOverhead:    new(uint64(0)),

	MaxSimulateAttempts:    new(uint(5)),
	MaxSubmitRetryAttempts: new(uint(10)),
	SubmitDelayDuration:    new(uint(3)),    // seconds
	TxExpirationSecs:       new(uint64(10)), // seconds
	MaxTxRetryAttempts:     new(uint64(5)),
	PruneIntervalSecs:      new(uint64(60 * 60 * 4)), // 4 hours
	PruneTxExpirationSecs:  new(uint64(60 * 60 * 2)), // 2 hours
}

// Resolve fills nil fields with defaults. After calling Resolve, all fields are guaranteed non-nil.
func (c *Config) Resolve() {
	if c.BroadcastChanSize == nil {
		c.BroadcastChanSize = new(*DefaultConfigSet.BroadcastChanSize)
	}
	if c.ConfirmPollSecs == nil {
		c.ConfirmPollSecs = new(*DefaultConfigSet.ConfirmPollSecs)
	}
	if c.DefaultMaxGasAmount == nil {
		c.DefaultMaxGasAmount = new(*DefaultConfigSet.DefaultMaxGasAmount)
	}
	if c.GasLimitOverhead == nil {
		c.GasLimitOverhead = new(*DefaultConfigSet.GasLimitOverhead)
	}
	if c.MaxSimulateAttempts == nil {
		c.MaxSimulateAttempts = new(*DefaultConfigSet.MaxSimulateAttempts)
	}
	if c.MaxSubmitRetryAttempts == nil {
		c.MaxSubmitRetryAttempts = new(*DefaultConfigSet.MaxSubmitRetryAttempts)
	}
	if c.SubmitDelayDuration == nil {
		c.SubmitDelayDuration = new(*DefaultConfigSet.SubmitDelayDuration)
	}
	if c.TxExpirationSecs == nil {
		c.TxExpirationSecs = new(*DefaultConfigSet.TxExpirationSecs)
	}
	if c.MaxTxRetryAttempts == nil {
		c.MaxTxRetryAttempts = new(*DefaultConfigSet.MaxTxRetryAttempts)
	}
	if c.PruneIntervalSecs == nil {
		c.PruneIntervalSecs = new(*DefaultConfigSet.PruneIntervalSecs)
	}
	if c.PruneTxExpirationSecs == nil {
		c.PruneTxExpirationSecs = new(*DefaultConfigSet.PruneTxExpirationSecs)
	}
}
