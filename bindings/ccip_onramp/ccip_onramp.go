package ccip_onramp

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_onramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp/onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIPOnramp interface {
	Address() aptos.AccountAddress

	Onramp() module_onramp.OnrampInterface
}

var _ CCIPOnramp = CCIPOnrampContract{}

type CCIPOnrampContract struct {
	address aptos.AccountAddress

	onramp module_onramp.OnrampInterface
}

func (c CCIPOnrampContract) Address() aptos.AccountAddress {
	return c.address
}

func (c CCIPOnrampContract) Onramp() module_onramp.OnrampInterface {
	return c.onramp
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_onramp.FunctionInfo,
)

func Compile(ccipAddress, mcmsAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_onramp":               ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPOnramp, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPOnramp {
	return CCIPOnrampContract{
		address: address,
		onramp:  module_onramp.NewOnramp(address, client),
	}
}

// DeployToExistingObject deploys the CCIP onramp package to an existing code object.
// This should not be used in production, where CCIP is deployed via MCMS and the
// offramp is deployed to the same object as CCIP.
func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	objectAddress, ccipAddress, mcmsAddress aptos.AccountAddress,
) (*api.PendingTransaction, CCIPOnramp, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.CCIPOnramp, namedAddresses, objectAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(objectAddress, client), nil
}
