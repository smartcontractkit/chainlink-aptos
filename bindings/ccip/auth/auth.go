// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_auth

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

type Auth interface {
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)

	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AssertIsRouter(opts *bind.TransactOpts, caller aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() AuthEncoder
}

type AuthEncoder interface {
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsRouter(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertOnlyOwner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"auth","name":"accept_ownership","parameters":null},{"package":"ccip","module":"auth","name":"assert_is_router","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"assert_only_owner","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip","module":"auth","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewAuth(address aptos.AccountAddress, client aptos.AptosRpcClient) Auth {
	contract := bind.NewBoundContract(address, "ccip", "auth", client)
	return AuthContract{
		BoundContract: contract,
		authEncoder:   authEncoder{BoundContract: contract},
	}
}

// Structs

type AuthState struct {
	RouterAddress aptos.AccountAddress `move:"address"`
}

type PendingRouterSignerCapability struct {
}

type AuthContract struct {
	*bind.BoundContract
	authEncoder
}

var _ Auth = AuthContract{}

func (c AuthContract) Encoder() AuthEncoder {
	return c.authEncoder
}

// View Functions

func (c AuthContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.Owner()
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

func (c AuthContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) AssertIsRouter(opts *bind.TransactOpts, caller aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.AssertIsRouter(caller)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type authEncoder struct {
	*bind.BoundContract
}

func (c authEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c authEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c authEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c authEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c authEncoder) AssertIsRouter(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_router", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c authEncoder) AssertOnlyOwner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_only_owner", nil, []string{
		"address",
	}, []any{
		caller,
	})
}
