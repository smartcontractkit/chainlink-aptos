package ccip_dummy_receiver

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_dummy_receiver "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_dummy_receiver/dummy_receiver"
	module_ptt_dummy_receiver "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_dummy_receiver/ptt_dummy_receiver"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIPDummyReceiver interface {
	Address() aptos.AccountAddress

	DummyReceiver() module_dummy_receiver.DummyReceiverInterface
	PTTDummyReceiver() module_ptt_dummy_receiver.PttDummyReceiverInterface
}

var _ CCIPDummyReceiver = CCIPDummyReceiverContract{}

type CCIPDummyReceiverContract struct {
	address aptos.AccountAddress

	dummyReceiver    module_dummy_receiver.DummyReceiverInterface
	pttDummyReceiver module_ptt_dummy_receiver.PttDummyReceiverInterface
}

func (C CCIPDummyReceiverContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPDummyReceiverContract) DummyReceiver() module_dummy_receiver.DummyReceiverInterface {
	return C.dummyReceiver
}

func (C CCIPDummyReceiverContract) PTTDummyReceiver() module_ptt_dummy_receiver.PttDummyReceiverInterface {
	return C.pttDummyReceiver
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_dummy_receiver.FunctionInfo,
	module_ptt_dummy_receiver.FunctionInfo,
)

func Compile(address aptos.AccountAddress, ccipAddress aptos.AccountAddress, mcmsAddress aptos.AccountAddress, deployer aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip_dummy_receiver":       address,
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
		"deployer":                  deployer,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPDummyReceiver, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPDummyReceiver {
	return CCIPDummyReceiverContract{
		address:          address,
		dummyReceiver:    module_dummy_receiver.NewDummyReceiver(address, client),
		pttDummyReceiver: module_ptt_dummy_receiver.NewPttDummyReceiver(address, client),
	}
}

const (
	DefaultSeed = "chainlink_ccip_dummy_receiver"
)

// DeployToObject deploys the dummmy receiver contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
//
// NOTE: This deployment method will NOT work with ptt_dummy_receiver module as it requires resource account.
// Use DeployToResourceAccount if you need PTT functionality.
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
		"deployer":                  auth.AccountAddress(), // Required for compilation, but ptt_dummy_receiver won't work with object deployment
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPDummyReceiver, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}

// DeployToResourceAccount deploys the dummy receiver contract to a new resource account.
// The address of that resource account is determined by the deployer account + an optional seed.
// If no seed is provided, the default seed DefaultSeed is used.
func DeployToResourceAccount(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress aptos.AccountAddress,
	seed ...string,
) (aptos.AccountAddress, *api.PendingTransaction, CCIPDummyReceiver, error) {
	dummyReceiverSeed := DefaultSeed
	if len(seed) > 0 {
		dummyReceiverSeed = seed[0]
	}
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
		"deployer":                  auth.AccountAddress(), // Origin account where Container is stored
	}
	address, tx, err := bind.DeployPackageToResourceAccount(auth, client, contracts.CCIPDummyReceiver, dummyReceiverSeed, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
