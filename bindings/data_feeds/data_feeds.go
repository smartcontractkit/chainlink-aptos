package data_feeds

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_registry "github.com/smartcontractkit/chainlink-aptos/bindings/data_feeds/registry"
	module_router "github.com/smartcontractkit/chainlink-aptos/bindings/data_feeds/router"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type DataFeeds interface {
	Address() aptos.AccountAddress

	Registry() module_registry.RegistryInterface
	Router() module_router.RouterInterface
}

var _ DataFeeds = DataFeedsContract{}

type DataFeedsContract struct {
	address aptos.AccountAddress

	registry module_registry.RegistryInterface
	router   module_router.RouterInterface
}

func (C DataFeedsContract) Address() aptos.AccountAddress {
	return C.address
}

func (C DataFeedsContract) Registry() module_registry.RegistryInterface {
	return C.registry
}
func (C DataFeedsContract) Router() module_router.RouterInterface {
	return C.router
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_registry.FunctionInfo,
	module_router.FunctionInfo,
)

func Compile(ownerAddress aptos.AccountAddress, platformAddress aptos.AccountAddress, ownerSecondaryAddress aptos.AccountAddress, platformSecondaryAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner":              ownerAddress,
		"platform":           platformAddress,
		"owner_secondary":    ownerSecondaryAddress,
		"platform_secondary": platformSecondaryAddress,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.DataFeeds, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) DataFeeds {
	return DataFeedsContract{
		address:  address,
		registry: module_registry.NewRegistry(address, client),
		router:   module_router.NewRouter(address, client),
	}
}

// DeployToObject deploys the Data Feeds contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ownerAddress aptos.AccountAddress,
	platformAddress aptos.AccountAddress,
	ownerSecondaryAddress aptos.AccountAddress,
	platformSecondaryAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, DataFeeds, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"owner":              ownerAddress,
		"platform":           platformAddress,
		"owner_secondary":    ownerSecondaryAddress,
		"platform_secondary": platformSecondaryAddress,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.DataFeeds, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}
