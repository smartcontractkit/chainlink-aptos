package mcms

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	module_mcms "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms"
	module_mcms_account "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms_account"
	module_mcms_deployer "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms_deployer"
	module_mcms_executor "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms_executor"
	module_mcms_registry "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms_registry"
)

type MCMS struct {
	Address aptos.AccountAddress

	MCMS         module_mcms.MCMS
	MCMSAccount  module_mcms_account.MCMSAccount
	MCMSDeployer module_mcms_deployer.MCMSDeployer
	MCMSExecutor module_mcms_executor.MCMSExecutor
	MCMSRegistry module_mcms_registry.MCMSRegistry
}

const (
	DefaultSeed = "chainlink_mcms"
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
	return MCMS{
		Address: address,
		MCMS: module_mcms.MCMS{
			MCMSCaller:     module_mcms.MCMSCaller{BoundContract: mcmsContract},
			MCMSTransactor: module_mcms.MCMSTransactor{BoundContract: mcmsContract},
		},
		MCMSAccount: module_mcms_account.MCMSAccount{
			MCMSAccountCaller:     module_mcms_account.MCMSAccountCaller{BoundContract: mcmsAccountContract},
			MCMSAccountTransactor: module_mcms_account.MCMSAccountTransactor{BoundContract: mcmsAccountContract},
		},
		MCMSDeployer: module_mcms_deployer.MCMSDeployer{
			MCMSDeployerTransactor: module_mcms_deployer.MCMSDeployerTransactor{BoundContract: mcmsDeployerContract},
		},
		MCMSExecutor: module_mcms_executor.MCMSExecutor{
			MCMSExecutorCaller:     module_mcms_executor.MCMSExecutorCaller{BoundContract: mcmsExecutorContract},
			MCMSExecutorTransactor: module_mcms_executor.MCMSExecutorTransactor{BoundContract: mcmsExecutorContract},
		},
		MCMSRegistry: module_mcms_registry.MCMSRegistry{
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
		return aptos.AccountAddress{}, nil, MCMS{}, err
	}

	return address, tx, Bind(address, client), nil
}
