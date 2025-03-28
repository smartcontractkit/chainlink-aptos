package ccip_router

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_router "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router/router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIPRouter interface {
	Address() aptos.AccountAddress

	Router() module_router.Router
}

var _ CCIPRouter = CCIPRouterContract{}

type CCIPRouterContract struct {
	address aptos.AccountAddress

	router module_router.Router
}

func (C CCIPRouterContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPRouterContract) Router() module_router.Router {
	return C.router
}

const (
	DefaultSeed = "chainlink_router"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_router.FunctionInfo,
)

func Compile(ccipAddress, mcmsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_router":               ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPRouter, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPRouter {
	return CCIPRouterContract{
		address: address,
		router:  module_router.NewRouter(address, client),
	}
}

// DeployToExistingObject deploys the CCIP router package to an existing code object.
// This should not be used in production, where CCIP is deployed via MCMS.
func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	objectAddress, ccipAddress, mcmsAddress aptos.AccountAddress,
) (*api.PendingTransaction, CCIPRouter, error) {
	// no need for mcms addresses since the router does not interact with mcms directly.
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.CCIPRouter, namedAddresses, objectAddress)
	if err != nil {
		return nil, CCIPRouterContract{}, err
	}
	return tx, Bind(objectAddress, client), nil
}
