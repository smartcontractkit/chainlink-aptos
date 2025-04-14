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

	Router() module_router.RouterInterface
}

var _ CCIPRouter = CCIPRouterContract{}

type CCIPRouterContract struct {
	address aptos.AccountAddress

	router module_router.RouterInterface
}

func (C CCIPRouterContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPRouterContract) Router() module_router.RouterInterface {
	return C.router
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_router.FunctionInfo,
)

func Compile(ccipAddress, mcmsAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_onramp":               ccipAddress,
		"ccip_router":               ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
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
// This should not be used in production, where CCIP is deployed via MCMS and the
// router is deployed to the same object as CCIP.
func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	objectAddress, ccipAddress, mcmsAddress aptos.AccountAddress,
) (*api.PendingTransaction, CCIPRouter, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_onramp":               ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.CCIPRouter, namedAddresses, objectAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(objectAddress, client), nil
}
