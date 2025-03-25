package mcms

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
	module_mcms_account "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_account"
	module_mcms_deployer "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_deployer"
	module_mcms_executor "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_executor"
	module_mcms_registry "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_registry"
)

type MCMS interface {
	Address() aptos.AccountAddress
	MCMS() module_mcms.MCMS
	MCMSAccount() module_mcms_account.MCMSAccount
	MCMSDeployer() module_mcms_deployer.MCMSDeployer
	MCMSExecutor() module_mcms_executor.MCMSExecutor
	MCMSRegistry() module_mcms_registry.MCMSRegistry
}

var _ MCMS = MCMSContract{}

type MCMSContract struct {
	address aptos.AccountAddress

	mcms         module_mcms.MCMS
	mcmsAccount  module_mcms_account.MCMSAccount
	mcmsDeployer module_mcms_deployer.MCMSDeployer
	mcmsExecutor module_mcms_executor.MCMSExecutor
	mcmsRegistry module_mcms_registry.MCMSRegistry
}

func (M MCMSContract) Address() aptos.AccountAddress {
	return M.address
}

func (M MCMSContract) MCMS() module_mcms.MCMS {
	return M.mcms
}

func (M MCMSContract) MCMSAccount() module_mcms_account.MCMSAccount {
	return M.mcmsAccount
}

func (M MCMSContract) MCMSDeployer() module_mcms_deployer.MCMSDeployer {
	return M.mcmsDeployer
}

func (M MCMSContract) MCMSExecutor() module_mcms_executor.MCMSExecutor {
	return M.mcmsExecutor
}

func (M MCMSContract) MCMSRegistry() module_mcms_registry.MCMSRegistry {
	return M.mcmsRegistry
}

const (
	DefaultSeed = "chainlink_mcms"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_mcms.FunctionInfo,
	module_mcms_account.FunctionInfo,
	module_mcms_deployer.FunctionInfo,
	module_mcms_executor.FunctionInfo,
	module_mcms_registry.FunctionInfo,
)

func Bind(
	address aptos.AccountAddress,
	client aptos.AptosRpcClient,
) MCMS {
	mcmsContract := bind.NewBoundContract(address, "mcms", client)
	mcmsAccountContract := bind.NewBoundContract(address, "mcms_account", client)
	mcmsDeployerContract := bind.NewBoundContract(address, "mcms_deployer", client)
	mcmsExecutorContract := bind.NewBoundContract(address, "mcms_executor", client)
	mcmsRegistryContract := bind.NewBoundContract(address, "mcms_registry", client)
	return MCMSContract{
		address: address,
		mcms: module_mcms.MCMSContract{
			MCMSCaller:     module_mcms.MCMSCaller{BoundContract: mcmsContract},
			MCMSTransactor: module_mcms.MCMSTransactor{BoundContract: mcmsContract},
		},
		mcmsAccount: module_mcms_account.MCMSAccountContract{
			MCMSAccountCaller:     module_mcms_account.MCMSAccountCaller{BoundContract: mcmsAccountContract},
			MCMSAccountTransactor: module_mcms_account.MCMSAccountTransactor{BoundContract: mcmsAccountContract},
		},
		mcmsDeployer: module_mcms_deployer.MCMSDeployerContract{
			MCMSDeployerTransactor: module_mcms_deployer.MCMSDeployerTransactor{BoundContract: mcmsDeployerContract},
		},
		mcmsExecutor: module_mcms_executor.MCMSExecutorContract{
			MCMSExecutorCaller:     module_mcms_executor.MCMSExecutorCaller{BoundContract: mcmsExecutorContract},
			MCMSExecutorTransactor: module_mcms_executor.MCMSExecutorTransactor{BoundContract: mcmsExecutorContract},
		},
		mcmsRegistry: module_mcms_registry.MCMSRegistryContract{
			MCMSRegistryCaller:     module_mcms_registry.MCMSRegistryCaller{BoundContract: mcmsRegistryContract},
			MCMSRegistryTransactor: module_mcms_registry.MCMSRegistryTransactor{BoundContract: mcmsRegistryContract},
		},
	}
}

// DeployToResourceAccount deploys the MCMS contract to a new resource account.
// The address of that resource account is determined by the deployer account + an optional seed.
// If no seed is provided, the default seed DefaultSeed is used.
// The initial owner will be the address of the deployer account.
func DeployToResourceAccount(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	seed ...string,
) (aptos.AccountAddress, *api.PendingTransaction, MCMS, error) {
	mcmsSeed := DefaultSeed
	if len(seed) > 0 {
		mcmsSeed = seed[0]
	}
	address, tx, err := bind.DeployPackageToResourceAccount(auth, client, "mcms", mcmsSeed, map[string]aptos.AccountAddress{
		"mcms_owner": auth.AccountAddress(),
	})
	if err != nil {
		return aptos.AccountAddress{}, nil, MCMSContract{}, err
	}

	return address, tx, Bind(address, client), nil
}
