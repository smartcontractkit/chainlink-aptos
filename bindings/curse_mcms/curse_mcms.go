package curse_mcms

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_curse_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/curse_mcms/curse_mcms"
	module_curse_mcms_account "github.com/smartcontractkit/chainlink-aptos/bindings/curse_mcms/curse_mcms_account"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CurseMCMS interface {
	Address() aptos.AccountAddress
	CurseMCMS() module_curse_mcms.CurseMCMSInterface
	CurseMCMSAccount() module_curse_mcms_account.CurseMCMSAccountInterface
}

var _ CurseMCMS = CurseMCMSContract{}

type CurseMCMSContract struct {
	address          aptos.AccountAddress
	curseMcms        module_curse_mcms.CurseMCMSInterface
	curseMcmsAccount module_curse_mcms_account.CurseMCMSAccountInterface
}

func (c CurseMCMSContract) Address() aptos.AccountAddress {
	return c.address
}

func (c CurseMCMSContract) CurseMCMS() module_curse_mcms.CurseMCMSInterface {
	return c.curseMcms
}

func (c CurseMCMSContract) CurseMCMSAccount() module_curse_mcms_account.CurseMCMSAccountInterface {
	return c.curseMcmsAccount
}

const (
	DefaultSeed = "chainlink_curse_mcms"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_curse_mcms.FunctionInfo,
	module_curse_mcms_account.FunctionInfo,
)

func Bind(
	address aptos.AccountAddress,
	client aptos.AptosRpcClient,
) CurseMCMS {
	return CurseMCMSContract{
		address:          address,
		curseMcms:        module_curse_mcms.NewCurseMCMS(address, client),
		curseMcmsAccount: module_curse_mcms_account.NewCurseMCMSAccount(address, client),
	}
}

func Compile(address, owner, ccipAddress, mcmsAddress, mcmsRegisterEntrypointsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"curse_mcms":                address,
		"curse_mcms_owner":          owner,
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": mcmsRegisterEntrypointsAddress,
	}
	return compile.CompilePackage(contracts.CurseMCMS, namedAddresses)
}

// DeployToResourceAccount deploys the CurseMCMS contract to a new resource account.
// The address of that resource account is determined by the deployer account + an optional seed.
// If no seed is provided, the default seed DefaultSeed is used.
// The initial owner will be the address of the deployer account.
func DeployToResourceAccount(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress, mcmsAddress, mcmsRegisterEntrypointsAddress aptos.AccountAddress,
	seed ...string,
) (aptos.AccountAddress, *api.PendingTransaction, CurseMCMS, error) {
	curseMCMSSeed := DefaultSeed
	if len(seed) > 0 {
		curseMCMSSeed = seed[0]
	}
	address, tx, err := bind.DeployPackageToResourceAccount(auth, client, contracts.CurseMCMS, curseMCMSSeed, map[string]aptos.AccountAddress{
		"curse_mcms_owner":          auth.AccountAddress(),
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": mcmsRegisterEntrypointsAddress,
	})
	if err != nil {
		return aptos.AccountAddress{}, nil, CurseMCMSContract{}, err
	}

	return address, tx, Bind(address, client), nil
}
