package regulated_token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_regulated_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/regulated_token_pool/regulated_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type RegulatedTokenPool interface {
	Address() aptos.AccountAddress

	RegulatedTokenPool() module_regulated_token_pool.RegulatedTokenPoolInterface
}

var _ RegulatedTokenPool = RegulatedTokenPoolContract{}

type RegulatedTokenPoolContract struct {
	address aptos.AccountAddress

	regulatedTokenPool module_regulated_token_pool.RegulatedTokenPoolInterface
}

func (c RegulatedTokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c RegulatedTokenPoolContract) RegulatedTokenPool() module_regulated_token_pool.RegulatedTokenPoolInterface {
	return c.regulatedTokenPool
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_regulated_token_pool.FunctionInfo,
)

func Compile(address, ccipAddress, mcmsAddress, ccipTokenPoolAddress, regulatedTokenAddress, adminAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"regulated_token_pool":      address,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"regulated_token":           regulatedTokenAddress,
		"mcms":                      mcmsAddress,
		"admin":                     adminAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPRegulatedTokenPool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) RegulatedTokenPool {
	return RegulatedTokenPoolContract{
		address:            address,
		regulatedTokenPool: module_regulated_token_pool.NewRegulatedTokenPool(address, client),
	}
}

// DeployToObject deploys the RegulatedTokenPool to a new named object.
// The token pool's administrator will be set to the deployer's account address.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress,
	adminAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (aptos.AccountAddress, *api.PendingTransaction, RegulatedTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"regulated_token":           localTokenAddress,
		"admin":                     adminAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPRegulatedTokenPool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
