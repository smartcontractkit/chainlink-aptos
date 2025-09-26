package managed_token

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_allowlist "github.com/smartcontractkit/chainlink-aptos/bindings/managed_token/allowlist"
	module_managed_token "github.com/smartcontractkit/chainlink-aptos/bindings/managed_token/managed_token"
	module_ownable "github.com/smartcontractkit/chainlink-aptos/bindings/managed_token/ownable"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type ManagedToken interface {
	Address() aptos.AccountAddress

	Allowlist() module_allowlist.AllowlistInterface
	ManagedToken() module_managed_token.ManagedTokenInterface
	Ownable() module_ownable.OwnableInterface
}

var _ ManagedToken = ManagedTokenContact{}

type ManagedTokenContact struct {
	address aptos.AccountAddress

	allowlist    module_allowlist.AllowlistInterface
	managedToken module_managed_token.ManagedTokenInterface
	ownable      module_ownable.OwnableInterface
}

func (l ManagedTokenContact) Address() aptos.AccountAddress {
	return l.address
}

func (l ManagedTokenContact) Allowlist() module_allowlist.AllowlistInterface {
	return l.allowlist
}

func (l ManagedTokenContact) ManagedToken() module_managed_token.ManagedTokenInterface {
	return l.managedToken
}

func (l ManagedTokenContact) Ownable() module_ownable.OwnableInterface {
	return l.ownable
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_allowlist.FunctionInfo,
	module_ownable.FunctionInfo,
	module_managed_token.FunctionInfo,
)

func Compile(address aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token": address,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.ManagedToken, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) ManagedToken {
	return ManagedTokenContact{
		address:      address,
		allowlist:    module_allowlist.NewAllowlist(address, client),
		managedToken: module_managed_token.NewManagedToken(address, client),
		ownable:      module_ownable.NewOwnable(address, client),
	}
}

// DeployToObject deploys the managed_token package to a new named object.
// The resulting address will be calculated using the deployer's account address and sequence number.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
) (aptos.AccountAddress, *api.PendingTransaction, ManagedToken, error) {
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.ManagedToken, nil)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}

// CompileMCMSRegistrar compiles the managed_token_mcms_registrar package
func CompileMCMSRegistrar(
	managedTokenAddress,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token":             managedTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.ManagedTokenMCMSRegistrar, namedAddresses)
}

// DeployMCMSRegistrarToExistingObject deploys the managed_token_mcms_registrar package to an existing code object (managedTokenAddress).
func DeployMCMSRegistrarToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	managedTokenAddress aptos.AccountAddress,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (*api.PendingTransaction, ManagedToken, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token":             managedTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.ManagedTokenMCMSRegistrar, namedAddresses, managedTokenAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(managedTokenAddress, client), nil
}
