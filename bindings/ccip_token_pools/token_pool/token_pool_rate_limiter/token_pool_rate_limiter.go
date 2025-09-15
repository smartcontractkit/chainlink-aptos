// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_token_pool_rate_limiter

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

type TokenPoolRateLimiterInterface interface {

	// Encoder returns the encoder implementation of this module.
	Encoder() TokenPoolRateLimiterEncoder
}

type TokenPoolRateLimiterEncoder interface {
	New() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DestroyRateLimiter(state RateLimitState) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_token_pool","module":"token_pool_rate_limiter","name":"destroy_rate_limiter","parameters":[{"name":"state","type":"RateLimitState"}]},{"package":"ccip_token_pool","module":"token_pool_rate_limiter","name":"new","parameters":null}]`

func NewTokenPoolRateLimiter(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenPoolRateLimiterInterface {
	contract := bind.NewBoundContract(address, "ccip_token_pool", "token_pool_rate_limiter", client)
	return TokenPoolRateLimiterContract{
		BoundContract:               contract,
		tokenPoolRateLimiterEncoder: tokenPoolRateLimiterEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_BUCKET_NOT_FOUND uint64 = 1
)

// Structs

type RateLimitState struct {
}

type TokensConsumed struct {
	RemoteChainSelector uint64 `move:"u64"`
	Tokens              uint64 `move:"u64"`
}

type ConfigChanged struct {
	RemoteChainSelector uint64 `move:"u64"`
	OutboundIsEnabled   bool   `move:"bool"`
	OutboundCapacity    uint64 `move:"u64"`
	OutboundRate        uint64 `move:"u64"`
	InboundIsEnabled    bool   `move:"bool"`
	InboundCapacity     uint64 `move:"u64"`
	InboundRate         uint64 `move:"u64"`
}

type TokenPoolRateLimiterContract struct {
	*bind.BoundContract
	tokenPoolRateLimiterEncoder
}

var _ TokenPoolRateLimiterInterface = TokenPoolRateLimiterContract{}

func (c TokenPoolRateLimiterContract) Encoder() TokenPoolRateLimiterEncoder {
	return c.tokenPoolRateLimiterEncoder
}

// View Functions

// Entry Functions

// Encoder
type tokenPoolRateLimiterEncoder struct {
	*bind.BoundContract
}

func (c tokenPoolRateLimiterEncoder) New() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{}, []any{})
}

func (c tokenPoolRateLimiterEncoder) DestroyRateLimiter(state RateLimitState) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("destroy_rate_limiter", nil, []string{
		"RateLimitState",
	}, []any{
		state,
	})
}
