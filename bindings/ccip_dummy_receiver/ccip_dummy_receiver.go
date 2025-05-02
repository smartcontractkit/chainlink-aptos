package ccip_dummy_receiver

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_dummy_receiver "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_dummy_receiver/dummy_receiver"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIPDummyReceiver interface {
	Address() aptos.AccountAddress

	DummyReceiver() module_dummy_receiver.DummyReceiverInterface
}

var _ CCIPDummyReceiver = CCIPDummyReceiverContract{}

type CCIPDummyReceiverContract struct {
	address aptos.AccountAddress

	dummyReceiver module_dummy_receiver.DummyReceiverInterface
}

func (C CCIPDummyReceiverContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPDummyReceiverContract) DummyReceiver() module_dummy_receiver.DummyReceiverInterface {
	return C.dummyReceiver
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_dummy_receiver.FunctionInfo,
)

func Compile(address aptos.AccountAddress, ccipAddress aptos.AccountAddress, mcmsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip_dummy_receiver":       address,
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPDummyReceiver, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPDummyReceiver {
	return CCIPDummyReceiverContract{
		address:       address,
		dummyReceiver: module_dummy_receiver.NewDummyReceiver(address, client),
	}
}

// DeployToObject deploys the dummy receiver contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, CCIPDummyReceiver, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPDummyReceiver, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
