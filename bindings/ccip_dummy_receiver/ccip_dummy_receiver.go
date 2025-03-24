package ccip_dummy_receiver

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_dummy_receiver "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_dummy_receiver/dummy_receiver"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

type CCIPDummyReceiver struct {
	Address aptos.AccountAddress

	DummyReceiver module_dummy_receiver.DummyReceiver
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_dummy_receiver.FunctionInfo,
)

func Compile(address aptos.AccountAddress, ccipAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip_dummy_receiver":                      address,
		"ccip": ccipAddress,
		"mcms": aptos.AccountZero,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	// Compile using CLI
	return compile.CompilePackage("ccip_dummy_receiver", namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPDummyReceiver {
	dummyReceiverContract := bind.NewBoundContract(address, "dummy_receiver", client)
	return CCIPDummyReceiver{
		Address: address,
		DummyReceiver: module_dummy_receiver.DummyReceiver{
			DummyReceiverCaller: module_dummy_receiver.DummyReceiverCaller{BoundContract: dummyReceiverContract},
			DummyReceiverTransactor: module_dummy_receiver.DummyReceiverTransactor{BoundContract: dummyReceiverContract},
		},
	}
}

// DeployToObject deploys the dummmy receiver contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, CCIPDummyReceiver, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip": ccipAddress,
		"mcms": aptos.AccountZero,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, "ccip_dummy_receiver", namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, CCIPDummyReceiver{}, err
	}
	return address, tx, Bind(address, client), nil
}
