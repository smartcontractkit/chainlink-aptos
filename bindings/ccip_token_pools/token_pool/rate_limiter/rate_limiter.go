// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_rate_limiter

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type RateLimiterInterface interface {

	// Encoder returns the encoder implementation of this module.
	Encoder() RateLimiterEncoder
}

type RateLimiterEncoder interface {
	New(isEnabled bool, capacity uint64, rate uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Min(a uint64, b uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_token_pool","module":"rate_limiter","name":"min","parameters":[{"name":"a","type":"u64"},{"name":"b","type":"u64"}]},{"package":"ccip_token_pool","module":"rate_limiter","name":"new","parameters":[{"name":"is_enabled","type":"bool"},{"name":"capacity","type":"u64"},{"name":"rate","type":"u64"}]}]`

func NewRateLimiter(address aptos.AccountAddress, client aptos.AptosRpcClient) RateLimiterInterface {
	contract := bind.NewBoundContract(address, "ccip_token_pool", "rate_limiter", client)
	return RateLimiterContract{
		BoundContract:      contract,
		rateLimiterEncoder: rateLimiterEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_TOKEN_MAX_CAPACITY_EXCEEDED uint64 = 1
	E_TOKEN_RATE_LIMIT_REACHED    uint64 = 2
)

// Structs

type TokenBucket struct {
	Tokens      uint64 `move:"u64"`
	LastUpdated uint64 `move:"u64"`
	IsEnabled   bool   `move:"bool"`
	Capacity    uint64 `move:"u64"`
	Rate        uint64 `move:"u64"`
}

type RateLimiterContract struct {
	*bind.BoundContract
	rateLimiterEncoder
}

var _ RateLimiterInterface = RateLimiterContract{}

func (c RateLimiterContract) Encoder() RateLimiterEncoder {
	return c.rateLimiterEncoder
}

// View Functions

// Entry Functions

// Encoder
type rateLimiterEncoder struct {
	*bind.BoundContract
}

func (c rateLimiterEncoder) New(isEnabled bool, capacity uint64, rate uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{
		"bool",
		"u64",
		"u64",
	}, []any{
		isEnabled,
		capacity,
		rate,
	})
}

func (c rateLimiterEncoder) Min(a uint64, b uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("min", nil, []string{
		"u64",
		"u64",
	}, []any{
		a,
		b,
	})
}
