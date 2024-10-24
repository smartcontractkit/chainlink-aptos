package txm

// TODO: these should be duration, not numbers
type Config struct {
	BroadcastChanSize uint
	ConfirmPollSecs   uint

	DefaultMaxGasAmount uint64
	MaxSimulateAttempts uint

	MaxSubmitRetryAttempts uint
	SubmitDelayDuration    uint
	TxExpirationSecs       uint64
	MaxTxRetryAttempts     uint64
	PruneIntervalSecs      uint64
	PruneTxExpirationSecs  uint64
}

// DefaultConfigSet is the default configuration for the TransactionManager
var DefaultConfigSet = Config{
	BroadcastChanSize: 100,
	ConfirmPollSecs:   2,

	// https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21
	DefaultMaxGasAmount: 200000,
	MaxSimulateAttempts: 5,

	MaxSubmitRetryAttempts: 10,
	SubmitDelayDuration:    3,  // seconds
	TxExpirationSecs:       10, // seconds
	MaxTxRetryAttempts:     5,
	PruneIntervalSecs:      uint64(60 * 60 * 4), // 4 hours
	PruneTxExpirationSecs:  uint64(60 * 60 * 2), // 2 hours
}
