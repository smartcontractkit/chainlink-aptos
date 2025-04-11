package mcms

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
	module_mcms_account "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_account"
	module_mcms_deployer "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_deployer"
	module_mcms_executor "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_executor"
	module_mcms_registry "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms_registry"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type MCMS interface {
	Address() aptos.AccountAddress
	MCMS() module_mcms.MCMSInterface
	MCMSAccount() module_mcms_account.MCMSAccountInterface
	MCMSDeployer() module_mcms_deployer.MCMSDeployerInterface
	MCMSExecutor() module_mcms_executor.MCMSExecutorInterface
	MCMSRegistry() module_mcms_registry.MCMSRegistryInterface
}

var _ MCMS = MCMSContract{}

type MCMSContract struct {
	address aptos.AccountAddress

	mcms         module_mcms.MCMSInterface
	mcmsAccount  module_mcms_account.MCMSAccountInterface
	mcmsDeployer module_mcms_deployer.MCMSDeployerInterface
	mcmsExecutor module_mcms_executor.MCMSExecutorInterface
	mcmsRegistry module_mcms_registry.MCMSRegistryInterface
}

func (M MCMSContract) Address() aptos.AccountAddress {
	return M.address
}

func (M MCMSContract) MCMS() module_mcms.MCMSInterface {
	return M.mcms
}

func (M MCMSContract) MCMSAccount() module_mcms_account.MCMSAccountInterface {
	return M.mcmsAccount
}

func (M MCMSContract) MCMSDeployer() module_mcms_deployer.MCMSDeployerInterface {
	return M.mcmsDeployer
}

func (M MCMSContract) MCMSExecutor() module_mcms_executor.MCMSExecutorInterface {
	return M.mcmsExecutor
}

func (M MCMSContract) MCMSRegistry() module_mcms_registry.MCMSRegistryInterface {
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
	return MCMSContract{
		address:      address,
		mcms:         module_mcms.NewMCMS(address, client),
		mcmsAccount:  module_mcms_account.NewMCMSAccount(address, client),
		mcmsDeployer: module_mcms_deployer.NewMCMSDeployer(address, client),
		mcmsExecutor: module_mcms_executor.NewMCMSExecutor(address, client),
		mcmsRegistry: module_mcms_registry.NewMCMSRegistry(address, client),
	}
}

func Compile(address, owner aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"mcms":       address,
		"mcms_owner": owner,
	}
	return compile.CompilePackage(contracts.MCMS, namedAddresses)
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
	address, tx, err := bind.DeployPackageToResourceAccount(auth, client, contracts.MCMS, mcmsSeed, map[string]aptos.AccountAddress{
		"mcms_owner": auth.AccountAddress(),
	})
	if err != nil {
		return aptos.AccountAddress{}, nil, MCMSContract{}, err
	}

	return address, tx, Bind(address, client), nil
}
