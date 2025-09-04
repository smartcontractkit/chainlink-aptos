package ccip_offramp

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_ocr3_base "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/ocr3_base"
	module_offramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/offramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIPOfframp interface {
	Address() aptos.AccountAddress

	Offramp() module_offramp.OfframpInterface
}

var _ CCIPOfframp = CCIPOfframpContract{}

type CCIPOfframpContract struct {
	address aptos.AccountAddress

	offramp module_offramp.OfframpInterface
}

func (c CCIPOfframpContract) Address() aptos.AccountAddress {
	return c.address
}

func (c CCIPOfframpContract) Offramp() module_offramp.OfframpInterface {
	return c.offramp
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_offramp.FunctionInfo,
	module_ocr3_base.FunctionInfo,
)

func Compile(ccipAddress, mcmsAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_offramp":              ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPOfframp, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIPOfframp {
	return CCIPOfframpContract{
		address: address,
		offramp: module_offramp.NewOfframp(address, client),
	}
}

// DeployToExistingObject deploys the CCIP offramp package to an existing code object.
// This should not be used in production, where CCIP is deployed via MCMS and the
// offramp is deployed to the same object as CCIP.
func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	objectAddress, ccipAddress, mcmsAddress aptos.AccountAddress,
) (*api.PendingTransaction, CCIPOfframp, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.CCIPOfframp, namedAddresses, objectAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(objectAddress, client), nil
}
