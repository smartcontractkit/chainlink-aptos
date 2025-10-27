// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_test_token

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type TestTokenInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error)

	Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string, enableDispatchHook bool) (*api.PendingTransaction, error)
	Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() TestTokenEncoder
}

type TestTokenEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string, enableDispatchHook bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertCanGetRefs(callerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"test_token","module":"test_token","name":"assert_can_get_refs","parameters":[{"name":"caller_address","type":"address"}]},{"package":"test_token","module":"test_token","name":"burn","parameters":[{"name":"from","type":"address"},{"name":"amount","type":"u64"}]},{"package":"test_token","module":"test_token","name":"initialize","parameters":[{"name":"max_supply","type":"0x1::option::Option\u003cu128\u003e"},{"name":"name","type":"0x1::string::String"},{"name":"symbol","type":"0x1::string::String"},{"name":"decimals","type":"u8"},{"name":"icon","type":"0x1::string::String"},{"name":"project","type":"0x1::string::String"},{"name":"enable_dispatch_hook","type":"bool"}]},{"package":"test_token","module":"test_token","name":"mint","parameters":[{"name":"to","type":"address"},{"name":"amount","type":"u64"}]},{"package":"test_token","module":"test_token","name":"token_state_address_internal","parameters":null}]`

func NewTestToken(address aptos.AccountAddress, client aptos.AptosRpcClient) TestTokenInterface {
	contract := bind.NewBoundContract(address, "test_token", "test_token", client)
	return TestTokenContract{
		BoundContract:    contract,
		testTokenEncoder: testTokenEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_NOT_PUBLISHER                              uint64 = 1
	E_NOT_ALLOWED_MINTER                         uint64 = 2
	E_NOT_ALLOWED_BURNER                         uint64 = 3
	E_TOKEN_NOT_INITIALIZED                      uint64 = 4
	E_TOKEN_ALREADY_INITIALIZED                  uint64 = 5
	E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED uint64 = 6
)

// Structs

type TokenStateDeployment struct {
}

type TokenState struct {
	Token bind.StdObject `move:"aptos_framework::object::Object"`
}

type TokenMetadataRefs struct {
}

type Initialize struct {
	Publisher aptos.AccountAddress `move:"address"`
	Token     bind.StdObject       `move:"aptos_framework::object::Object"`
	MaxSupply **big.Int            `move:"0x1::option::Option<u128>"`
	Decimals  byte                 `move:"u8"`
	Icon      string               `move:"0x1::string::String"`
	Project   string               `move:"0x1::string::String"`
}

type Mint struct {
	Minter aptos.AccountAddress `move:"address"`
	To     aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type Burn struct {
	Burner aptos.AccountAddress `move:"address"`
	From   aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type DepositHook struct {
	Account aptos.AccountAddress `move:"address"`
	Amount  uint64               `move:"u64"`
}

type WithdrawHook struct {
	Account aptos.AccountAddress `move:"address"`
	Amount  uint64               `move:"u64"`
}

type TestTokenContract struct {
	*bind.BoundContract
	testTokenEncoder
}

var _ TestTokenInterface = TestTokenContract{}

func (c TestTokenContract) Encoder() TestTokenEncoder {
	return c.testTokenEncoder
}

// View Functions

func (c TestTokenContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.TypeAndVersion()
	if err != nil {
		return *new(string), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(string), err
	}

	var (
		r0 string
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(string), err
	}
	return r0, nil
}

func (c TestTokenContract) TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.TokenStateAddress()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

func (c TestTokenContract) TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.TokenMetadata()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

// Entry Functions

func (c TestTokenContract) Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string, enableDispatchHook bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.Initialize(maxSupply, name, symbol, decimals, icon, project, enableDispatchHook)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TestTokenContract) Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.Mint(to, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TestTokenContract) Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.testTokenEncoder.Burn(from, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type testTokenEncoder struct {
	*bind.BoundContract
}

func (c testTokenEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c testTokenEncoder) TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address", nil, []string{}, []any{})
}

func (c testTokenEncoder) TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata", nil, []string{}, []any{})
}

func (c testTokenEncoder) Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string, enableDispatchHook bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"0x1::option::Option<u128>",
		"0x1::string::String",
		"0x1::string::String",
		"u8",
		"0x1::string::String",
		"0x1::string::String",
		"bool",
	}, []any{
		maxSupply,
		name,
		symbol,
		decimals,
		icon,
		project,
		enableDispatchHook,
	})
}

func (c testTokenEncoder) Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mint", nil, []string{
		"address",
		"u64",
	}, []any{
		to,
		amount,
	})
}

func (c testTokenEncoder) Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("burn", nil, []string{
		"address",
		"u64",
	}, []any{
		from,
		amount,
	})
}

func (c testTokenEncoder) TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address_internal", nil, []string{}, []any{})
}

func (c testTokenEncoder) AssertCanGetRefs(callerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_can_get_refs", nil, []string{
		"address",
	}, []any{
		callerAddress,
	})
}
