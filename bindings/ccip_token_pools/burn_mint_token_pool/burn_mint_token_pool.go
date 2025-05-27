package burn_mint_token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_burn_mint_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/burn_mint_token_pool/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type BurnMintTokenPool interface {
	Address() aptos.AccountAddress

	BurnMintTokenPool() module_burn_mint_token_pool.BurnMintTokenPoolInterface
}

var _ BurnMintTokenPool = BurnMintTokenPoolContract{}

type BurnMintTokenPoolContract struct {
	address aptos.AccountAddress

	burnMintTokenPool module_burn_mint_token_pool.BurnMintTokenPoolInterface
}

func (c BurnMintTokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c BurnMintTokenPoolContract) BurnMintTokenPool() module_burn_mint_token_pool.BurnMintTokenPoolInterface {
	return c.burnMintTokenPool
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_burn_mint_token_pool.FunctionInfo,
)

func Compile(address, ccipAddress, mcmsAddress, ccipTokenPoolAddress, localTokenAddress, tokenPoolAdministrator aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"burn_mint_token_pool":      address,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"burn_mint_local_token":     localTokenAddress,
		"token_pool_administrator":  tokenPoolAdministrator,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPBurnMintPool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) BurnMintTokenPool {
	return BurnMintTokenPoolContract{
		address:           address,
		burnMintTokenPool: module_burn_mint_token_pool.NewBurnMintTokenPool(address, client),
	}
}

// DeployToObject deploys the BurnMintTokenPool to a new named object.
// The token pool's administrator will be set to the deployer's account address.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, BurnMintTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"burn_mint_local_token":     localTokenAddress,
		"token_pool_administrator":  auth.AccountAddress(),
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPBurnMintPool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
