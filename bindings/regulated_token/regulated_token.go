package regulated_token

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_regulated_token "github.com/smartcontractkit/chainlink-aptos/bindings/regulated_token/regulated_token"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type RegulatedToken interface {
	Address() aptos.AccountAddress

	RegulatedToken() module_regulated_token.RegulatedTokenInterface
}

var _ RegulatedToken = RegulatedTokenContact{}

type RegulatedTokenContact struct {
	address aptos.AccountAddress

	regulatedToken module_regulated_token.RegulatedTokenInterface
}

func (l RegulatedTokenContact) Address() aptos.AccountAddress {
	return l.address
}

func (l RegulatedTokenContact) RegulatedToken() module_regulated_token.RegulatedTokenInterface {
	return l.regulatedToken
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_regulated_token.FunctionInfo,
)

func Compile(address, adminAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"regulated_token": address,
		"admin":           adminAddress,
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.RegulatedToken, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) RegulatedToken {
	return RegulatedTokenContact{
		address:        address,
		regulatedToken: module_regulated_token.NewRegulatedToken(address, client),
	}
}

// DeployToObject deploys the regulated_token package to a new named object.
// The resulting address will be calculated using the deployer's account address and sequence number.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	adminAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, RegulatedToken, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"admin": adminAddress,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.RegulatedToken, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}

// CompileMCMSRegistrar compiles the regulated_token_mcms_registrar package
func CompileMCMSRegistrar(
	regulatedTokenAddress, adminAddress, mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"regulated_token":           regulatedTokenAddress,
		"admin":                     adminAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.RegulatedTokenMCMSRegistrar, namedAddresses)
}

// DeployMCMSRegistrarToExistingObject deploys the regulated_token_mcms_registrar package to an existing code object (regulatedTokenAddress).
func DeployMCMSRegistrarToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	regulatedTokenAddress aptos.AccountAddress,
	adminAddress aptos.AccountAddress,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (*api.PendingTransaction, RegulatedToken, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"regulated_token":           regulatedTokenAddress,
		"admin":                     adminAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.RegulatedTokenMCMSRegistrar, namedAddresses, regulatedTokenAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(regulatedTokenAddress, client), nil
}
