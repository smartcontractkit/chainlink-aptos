package test_token

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	module_test_token "github.com/smartcontractkit/chainlink-aptos/bindings/test_token/test_token/test_token"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type TestToken interface {
	Address() aptos.AccountAddress

	TestToken() module_test_token.TestTokenInterface
}

var _ TestToken = TestTokenContract{}

type TestTokenContract struct {
	address aptos.AccountAddress

	testToken module_test_token.TestTokenInterface
}

func (m TestTokenContract) Address() aptos.AccountAddress {
	return m.address
}

func (m TestTokenContract) TestToken() module_test_token.TestTokenInterface {
	return m.testToken
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_test_token.FunctionInfo,
)

func Compile(address aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"test_token": address,
	}
	return compile.CompilePackage(contracts.TestToken, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) TestToken {
	return TestTokenContract{
		address:   address,
		testToken: module_test_token.NewTestToken(address, client),
	}
}

func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
) (aptos.AccountAddress, *api.PendingTransaction, TestToken, error) {
	namedAddresses := map[string]aptos.AccountAddress{}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.TestToken, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, TestTokenContract{}, err
	}
	return address, tx, Bind(address, client), nil
}
