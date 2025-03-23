package cciprouter

import (
	"github.com/aptos-labs/aptos-go-sdk"

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

func Compile(CCIPAddress aptos.AccountAddress, mcmsAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      CCIPAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = CCIPAddress
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
