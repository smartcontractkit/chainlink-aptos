package lnr_registrar

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_lnr_registrar "github.com/smartcontractkit/chainlink-aptos/bindings/test_token/lnr_registrar/lnr_registrar"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type LnRRegistrar interface {
	Address() aptos.AccountAddress

	LnRRegistrar() module_lnr_registrar.LnrRegistrarInterface
}

var _ LnRRegistrar = LnRRegistrarContract{}

type LnRRegistrarContract struct {
	address aptos.AccountAddress

	lnrRegistrar module_lnr_registrar.LnrRegistrarInterface
}

func (m LnRRegistrarContract) Address() aptos.AccountAddress {
	return m.address
}

func (m LnRRegistrarContract) LnRRegistrar() module_lnr_registrar.LnrRegistrarInterface {
	return m.lnrRegistrar
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_lnr_registrar.FunctionInfo,
)

func Compile(
	address aptos.AccountAddress,
	testTokenAddress aptos.AccountAddress,
	lockReleaseTokenPoolAddress aptos.AccountAddress,
	ccipAddress, ccipTokenPoolAddress, mcmsAddress, lockReleaseLocalTokenAddress aptos.AccountAddress,
) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"lnr_registrar":             address,
		"test_token":                testTokenAddress,
		"lock_release_token_pool":   lockReleaseTokenPoolAddress,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"mcms":                      mcmsAddress,
		"lock_release_local_token":  lockReleaseLocalTokenAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	return compile.CompilePackage(contracts.TestTokenLnRRegistrar, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) LnRRegistrar {
	return LnRRegistrarContract{
		address:      address,
		lnrRegistrar: module_lnr_registrar.NewLnrRegistrar(address, client),
	}
}

func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	testTokenAddress aptos.AccountAddress,
	lockReleaseTokenPoolAddress aptos.AccountAddress,
	ccipAddress, ccipTokenPoolAddress, mcmsAddress, lockReleaseLocalTokenAddress aptos.AccountAddress,
) (*api.PendingTransaction, LnRRegistrar, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"test_token":                testTokenAddress,
		"lock_release_token_pool":   lockReleaseTokenPoolAddress,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"mcms":                      mcmsAddress,
		"lock_release_local_token":  lockReleaseLocalTokenAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.TestTokenLnRRegistrar, namedAddresses, testTokenAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(testTokenAddress, client), nil
}
