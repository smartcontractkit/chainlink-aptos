package mcmstest

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_mcms_user "github.com/smartcontractkit/chainlink-aptos/bindings/mcms_test/mcms_user"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type MCMSTest interface {
	Address() aptos.AccountAddress

	MCMSUser() module_mcms_user.MCMSUserInterface
}

var _ MCMSTest = MCMSTestContract{}

type MCMSTestContract struct {
	address aptos.AccountAddress

	mcmsUser module_mcms_user.MCMSUserInterface
}

func (M MCMSTestContract) Address() aptos.AccountAddress {
	return M.address
}

func (M MCMSTestContract) MCMSUser() module_mcms_user.MCMSUserInterface {
	return M.mcmsUser
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_mcms_user.FunctionInfo,
)

func Compile(address, mcmsAddress aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"mcms_test": mcmsAddress,
		"mcms":      mcmsAddress,
	}
	return compile.CompilePackage(contracts.MCMSTest, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSTest {
	return MCMSTestContract{
		address:  address,
		mcmsUser: module_mcms_user.NewMCMSUser(address, client),
	}
}

func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	mcmsAddress aptos.AccountAddress,
) (aptos.AccountAddress, *api.PendingTransaction, MCMSTest, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"mcms": mcmsAddress,
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.MCMSTest, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, MCMSTestContract{}, err
	}
	return address, tx, Bind(address, client), nil
}
