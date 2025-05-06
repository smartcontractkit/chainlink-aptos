package platform

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_forwarder "github.com/smartcontractkit/chainlink-aptos/bindings/platform/forwarder"
	module_storage "github.com/smartcontractkit/chainlink-aptos/bindings/platform/storage"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type Platform interface {
	Address() aptos.AccountAddress

	Forwarder() module_forwarder.ForwarderInterface
	Storage() module_storage.StorageInterface
}

var _ Platform = PlatformContract{}

type PlatformContract struct {
	address aptos.AccountAddress

	forwarder module_forwarder.ForwarderInterface
	storage   module_storage.StorageInterface
}

func (C PlatformContract) Address() aptos.AccountAddress {
	return C.address
}

func (C PlatformContract) Forwarder() module_forwarder.ForwarderInterface {
	return C.forwarder
}
func (C PlatformContract) Storage() module_storage.StorageInterface {
	return C.storage
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_forwarder.FunctionInfo,
	module_storage.FunctionInfo,
)

func Compile(ownerAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner": ownerAddress,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.Platform, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) Platform {
	return PlatformContract{
		address:   address,
		forwarder: module_forwarder.NewForwarder(address, client),
		storage:   module_storage.NewStorage(address, client),
	}
}

// DeployToObject deploys the Platform contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ownerAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, Platform, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner": ownerAddress,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.Platform, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
