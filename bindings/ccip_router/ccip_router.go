package cciprouter

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_router "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router/router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

type CCIPRouter struct {
	Address aptos.AccountAddress

	Router module_router.Router
}

const (
	DefaultSeed = "chainlink_router"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_router.FunctionInfo,
)

func Compile(ccipAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      aptos.AccountZero,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	// Compile using CLI
	return compile.CompilePackage("ccip_router", namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPRouter {
	router := bind.NewBoundContract(address, "router", client)
	return CCIPRouter{
		Address: address,
		Router: module_router.Router{
			RouterCaller:     module_router.RouterCaller{BoundContract: router},
			RouterTransactor: module_router.RouterTransactor{BoundContract: router},
		},
	}
}

// DeployToExistingObject deploys the CCIP router package to an existing code object.
// This should not be used in production, where CCIP is deployed via MCMS.
func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	objectAddress aptos.AccountAddress,
	ccipAddress aptos.AccountAddress,
) (*api.PendingTransaction, CCIPRouter, error) {
	// no need for mcms addresses since the router does not interact with mcms directly.
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      aptos.AccountZero,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, "ccip_router", namedAddresses, objectAddress)
	if err != nil {
		return nil, CCIPRouter{}, err
	}
	return tx, Bind(objectAddress, client), nil
}
