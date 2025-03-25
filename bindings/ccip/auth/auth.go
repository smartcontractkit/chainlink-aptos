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
}

const FunctionInfo = `[{"package":"ccip","module":"auth","name":"accept_ownership","parameters":null},{"package":"ccip","module":"auth","name":"assert_is_router","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"assert_only_owner","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip","module":"auth","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

// Structs

type AuthState struct {
	RouterAddress aptos.AccountAddress `move:"address"`
}

type PendingRouterSignerCapability struct {
}

type AuthContract struct {
	AuthCaller
	AuthTransactor
}

// View Functions

type AuthCaller struct {
	*bind.BoundContract
}

func (c AuthCaller) EncodeOwner() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c AuthCaller) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeOwner()
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

type AuthTransactor struct {
	*bind.BoundContract
}

func (c AuthTransactor) EncodeTransferOwnership(to aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c AuthTransactor) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeTransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthTransactor) EncodeAcceptOwnership() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c AuthTransactor) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeAcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthTransactor) EncodeExecuteOwnershipTransfer(to aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c AuthTransactor) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthTransactor) EncodeAssertIsRouter(caller aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_router", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c AuthTransactor) AssertIsRouter(opts *bind.TransactOpts, caller aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeAssertIsRouter(caller)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c AuthCaller) EncodeAssertOnlyOwner(caller aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_only_owner", nil, []string{
		"address",
	}, []any{
		caller,
	})
}
