package curse_mcms

import (
	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_curse_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/curse_mcms/curse_mcms"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CurseMCMS interface {
	Address() aptos.AccountAddress
	CurseMCMS() module_curse_mcms.CurseMCMSInterface
}

var _ CurseMCMS = CurseMCMSContract{}

type CurseMCMSContract struct {
	address   aptos.AccountAddress
	curseMcms module_curse_mcms.CurseMCMSInterface
}

func (c CurseMCMSContract) Address() aptos.AccountAddress {
	return c.address
}

func (c CurseMCMSContract) CurseMCMS() module_curse_mcms.CurseMCMSInterface {
	return c.curseMcms
}

const (
	DefaultSeed = "chainlink_curse_mcms"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_curse_mcms.FunctionInfo,
)

func Bind(
	address aptos.AccountAddress,
	client aptos.AptosRpcClient,
) CurseMCMS {
	return CurseMCMSContract{
		address:   address,
		curseMcms: module_curse_mcms.NewCurseMCMS(address, client),
	}
}

func Compile(address aptos.AccountAddress, ccipAddress aptos.AccountAddress, mcmsAddress aptos.AccountAddress, mcmsRegisterEntrypointsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"curse_mcms":                address,
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": mcmsRegisterEntrypointsAddress,
	}
	return compile.CompilePackage(contracts.CurseMCMS, namedAddresses)
}
