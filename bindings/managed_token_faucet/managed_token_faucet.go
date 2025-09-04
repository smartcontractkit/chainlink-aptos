package managed_token_faucet

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_faucet "github.com/smartcontractkit/chainlink-aptos/bindings/managed_token_faucet/faucet"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type ManagedTokenFaucet interface {
	Address() aptos.AccountAddress

	Faucet() module_faucet.FaucetInterface
}

var _ ManagedTokenFaucet = ManagedTokenFaucetContract{}

type ManagedTokenFaucetContract struct {
	address aptos.AccountAddress

	faucet module_faucet.FaucetInterface
}

func (m ManagedTokenFaucetContract) Address() aptos.AccountAddress {
	return m.address
}

func (m ManagedTokenFaucetContract) Faucet() module_faucet.FaucetInterface {
	return m.faucet
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_faucet.FunctionInfo,
)

func Compile(address aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token": address,
	}
	return compile.CompilePackage(contracts.ManagedTokenFaucet, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) ManagedTokenFaucet {
	return ManagedTokenFaucetContract{
		address: address,
		faucet:  module_faucet.NewFaucet(address, client),
	}
}

func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	managedTokenAddress aptos.AccountAddress,
) (*api.PendingTransaction, ManagedTokenFaucet, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"managed_token": managedTokenAddress,
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.ManagedTokenFaucet, namedAddresses, managedTokenAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(managedTokenAddress, client), nil
}
