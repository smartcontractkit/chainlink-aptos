package bnm_registrar

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_bnm_registrar "github.com/smartcontractkit/chainlink-aptos/bindings/test_token/bnm_registrar/bnm_registrar"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type BnMRegistrar interface {
	Address() aptos.AccountAddress

	BnMRegistrar() module_bnm_registrar.BnmRegistrarInterface
}

var _ BnMRegistrar = BnMRegistrarContract{}

type BnMRegistrarContract struct {
	address aptos.AccountAddress

	bnmRegistrar module_bnm_registrar.BnmRegistrarInterface
}

func (m BnMRegistrarContract) Address() aptos.AccountAddress {
	return m.address
}

func (m BnMRegistrarContract) BnMRegistrar() module_bnm_registrar.BnmRegistrarInterface {
	return m.bnmRegistrar
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_bnm_registrar.FunctionInfo,
)

func Compile(
	address aptos.AccountAddress,
	testTokenAddress aptos.AccountAddress,
	burnMintTokenPoolAddress aptos.AccountAddress,
	ccipAddress, ccipTokenPoolAddress, mcmsAddress, burnMintLocalTokenAddress aptos.AccountAddress,
) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"bnm_registrar":             address,
		"test_token":                testTokenAddress,
		"burn_mint_token_pool":      burnMintTokenPoolAddress,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"mcms":                      mcmsAddress,
		"burn_mint_local_token":     burnMintLocalTokenAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	return compile.CompilePackage(contracts.TestTokenBnMRegistrar, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) BnMRegistrar {
	return BnMRegistrarContract{
		address:      address,
		bnmRegistrar: module_bnm_registrar.NewBnmRegistrar(address, client),
	}
}

func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	testTokenAddress aptos.AccountAddress,
	burnMintTokenPoolAddress aptos.AccountAddress,
	ccipAddress, ccipTokenPoolAddress, mcmsAddress, burnMintLocalTokenAddress aptos.AccountAddress,
) (*api.PendingTransaction, BnMRegistrar, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"test_token":                testTokenAddress,
		"burn_mint_token_pool":      burnMintTokenPoolAddress,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"mcms":                      mcmsAddress,
		"burn_mint_local_token":     burnMintLocalTokenAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.TestTokenBnMRegistrar, namedAddresses, testTokenAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(testTokenAddress, client), nil
}
