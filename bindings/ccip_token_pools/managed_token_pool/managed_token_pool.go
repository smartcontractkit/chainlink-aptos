package managed_token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_managed_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/managed_token_pool/managed_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type ManagedTokenPool interface {
	Address() aptos.AccountAddress

	ManagedTokenPool() module_managed_token_pool.ManagedTokenPoolInterface
}

var _ ManagedTokenPool = ManagedTokenPoolContract{}

type ManagedTokenPoolContract struct {
	address aptos.AccountAddress

	burnMintTokenPool module_managed_token_pool.ManagedTokenPoolInterface
}

func (c ManagedTokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c ManagedTokenPoolContract) ManagedTokenPool() module_managed_token_pool.ManagedTokenPoolInterface {
	return c.burnMintTokenPool
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_managed_token_pool.FunctionInfo,
)

func Compile(address, ccipAddress, mcmsAddress, ccipTokenPoolAddress, managedTokenAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token_pool":        address,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"managed_token":             managedTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPManagedTokenPool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) ManagedTokenPool {
	return ManagedTokenPoolContract{
		address:           address,
		burnMintTokenPool: module_managed_token_pool.NewManagedTokenPool(address, client),
	}
}

// DeployToObject deploys the ManagedTokenPool to a new named object.
// The token pool's administrator will be set to the deployer's account address.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, ManagedTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"burn_mint_local_token":     localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPBurnMintPool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
