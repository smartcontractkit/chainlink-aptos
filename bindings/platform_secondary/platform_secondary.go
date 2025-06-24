package platform_secondary

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_forwarder "github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary/forwarder"
	module_storage "github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary/storage"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type PlatformSecondary interface {
	Address() aptos.AccountAddress

	Forwarder() module_forwarder.ForwarderInterface
	Storage() module_storage.StorageInterface
}

var _ PlatformSecondary = PlatformSecondaryContract{}

type PlatformSecondaryContract struct {
	address aptos.AccountAddress

	forwarder module_forwarder.ForwarderInterface
	storage   module_storage.StorageInterface
}

func (C PlatformSecondaryContract) Address() aptos.AccountAddress {
	return C.address
}

func (C PlatformSecondaryContract) Forwarder() module_forwarder.ForwarderInterface {
	return C.forwarder
}
func (C PlatformSecondaryContract) Storage() module_storage.StorageInterface {
	return C.storage
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_forwarder.FunctionInfo,
	module_storage.FunctionInfo,
)

func Compile(ownerAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner_secondary": ownerAddress,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.PlatformSecondary, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) PlatformSecondary {
	return PlatformSecondaryContract{
		address:   address,
		forwarder: module_forwarder.NewForwarder(address, client),
		storage:   module_storage.NewStorage(address, client),
	}
}

// DeployToObject deploys the PlatformSecondary contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ownerAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, PlatformSecondary, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner_secondary": ownerAddress,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.PlatformSecondary, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
