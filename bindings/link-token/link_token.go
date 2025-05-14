package link_token

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_allowlist "github.com/smartcontractkit/chainlink-aptos/bindings/link-token/allowlist"
	module_link_token "github.com/smartcontractkit/chainlink-aptos/bindings/link-token/link_token"
	module_ownable "github.com/smartcontractkit/chainlink-aptos/bindings/link-token/ownable"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type LinkToken interface {
	Address() aptos.AccountAddress

	Allowlist() module_allowlist.AllowlistInterface
	LinkToken() module_link_token.LinkTokenInterface
	Ownable() module_ownable.OwnableInterface
}

var _ LinkToken = LinkTokenContact{}

type LinkTokenContact struct {
	address aptos.AccountAddress

	allowlist module_allowlist.AllowlistInterface
	linkToken module_link_token.LinkTokenInterface
	ownable   module_ownable.OwnableInterface
}

func (l LinkTokenContact) Address() aptos.AccountAddress {
	return l.address
}

func (l LinkTokenContact) Allowlist() module_allowlist.AllowlistInterface {
	return l.allowlist
}

func (l LinkTokenContact) LinkToken() module_link_token.LinkTokenInterface {
	return l.linkToken
}

func (l LinkTokenContact) Ownable() module_ownable.OwnableInterface {
	return l.ownable
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_allowlist.FunctionInfo,
	module_ownable.FunctionInfo,
)

func Compile(address aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"link": address,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.LinkToken, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) LinkToken {
	return LinkTokenContact{
		address:   address,
		allowlist: module_allowlist.NewAllowlist(address, client),
		ownable:   module_ownable.NewOwnable(address, client),
	}
}

// DeployToObject deploys the link-token package to a new named object.
// The resulting address will be calculated using the deployer's account address and sequence number.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
) (aptos.AccountAddress, *api.PendingTransaction, LinkToken, error) {
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.LinkToken, nil)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}

// CompileMCMSRegistrar compiles the mcms-registrar package
func CompileMCMSRegistrar(
	linkTokenAddress,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"link":                      linkTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.MCMSRegistrar, namedAddresses)
}

// DeployMCMSRegistrarToExistingObject deploys the mcms-registrar package to an existing code object (linkAddress).
func DeployMCMSRegistrarToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	linkAddress,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (*api.PendingTransaction, LinkToken, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"link":                      linkAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.MCMSRegistrar, namedAddresses, linkAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(linkAddress, client), nil
}
