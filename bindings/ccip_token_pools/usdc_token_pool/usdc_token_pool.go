package usdc_token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_usdc_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/usdc_token_pool/usdc_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type USDCTokenPool interface {
	Address() aptos.AccountAddress

	UsdcTokenPool() module_usdc_token_pool.USDCTokenPoolInterface
}

var _ USDCTokenPool = USDCTokenPoolContract{}

type USDCTokenPoolContract struct {
	address aptos.AccountAddress

	usdcTokenPool module_usdc_token_pool.USDCTokenPoolInterface
}

func (c USDCTokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c USDCTokenPoolContract) UsdcTokenPool() module_usdc_token_pool.USDCTokenPoolInterface {
	return c.usdcTokenPool
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_usdc_token_pool.FunctionInfo,
)

func Compile(
	address,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress,
	messageTransmitter,
	tokenMessengerMinter,
	aptosExtensions,
	stablecoin,
	deployer aptos.AccountAddress,
	registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"usdc_token_pool":           address,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"local_token":               localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
		"message_transmitter":       messageTransmitter,
		"token_messenger_minter":    tokenMessengerMinter,
		"aptos_extensions":          aptosExtensions,
		"stablecoin":                stablecoin,
		"deployer":                  deployer,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPUSDCTokenPool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) USDCTokenPool {
	return USDCTokenPoolContract{
		address:       address,
		usdcTokenPool: module_usdc_token_pool.NewUSDCTokenPool(address, client),
	}
}

// DeployToObject deploys the USDCTokenPool to a new named object.
// The token pool's administrator will be set to the deployer's account address.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress,
	messageTransmitter,
	tokenMessengerMinter,
	aptosExtensions,
	stablecoin,
	deployer aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, USDCTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"local_token":               localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
		"message_transmitter":       messageTransmitter,
		"token_messenger_minter":    tokenMessengerMinter,
		"aptos_extensions":          aptosExtensions,
		"stablecoin":                stablecoin,
		"deployer":                  deployer,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPUSDCTokenPool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
