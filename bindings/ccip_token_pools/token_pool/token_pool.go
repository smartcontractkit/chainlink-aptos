package token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_rate_limiter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter"
	module_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/token_pool"
	module_token_pool_rate_limiter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/token_pool_rate_limiter"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type TokenPool interface {
	Address() aptos.AccountAddress

	RateLimiter() module_rate_limiter.RateLimiterInterface
	TokenPool() module_token_pool.TokenPoolInterface
	TokenPoolRateLimiter() module_token_pool_rate_limiter.TokenPoolRateLimiterInterface
}

var _ TokenPool = TokenPoolContract{}

type TokenPoolContract struct {
	address aptos.AccountAddress

	rateLimiter          module_rate_limiter.RateLimiterInterface
	tokenPool            module_token_pool.TokenPoolInterface
	tokenPoolRateLimiter module_token_pool_rate_limiter.TokenPoolRateLimiterInterface
}

func (c TokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c TokenPoolContract) RateLimiter() module_rate_limiter.RateLimiterInterface {
	return c.rateLimiter
}

func (c TokenPoolContract) TokenPool() module_token_pool.TokenPoolInterface {
	return c.tokenPool
}

func (c TokenPoolContract) TokenPoolRateLimiter() module_token_pool_rate_limiter.TokenPoolRateLimiterInterface {
	return c.tokenPoolRateLimiter
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_rate_limiter.FunctionInfo,
	module_token_pool.FunctionInfo,
	module_token_pool_rate_limiter.FunctionInfo,
)

func Compile(address, ccipAddress, mcmsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip_token_pool":           address,
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPTokenPool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenPool {
	return TokenPoolContract{
		address:              address,
		rateLimiter:          module_rate_limiter.NewRateLimiter(address, client),
		tokenPool:            module_token_pool.NewTokenPool(address, client),
		tokenPoolRateLimiter: module_token_pool_rate_limiter.NewTokenPoolRateLimiter(address, client),
	}
}

// DeployToObject deploys the token_pool package to a new named object.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, TokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPTokenPool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
