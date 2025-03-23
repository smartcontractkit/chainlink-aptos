// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms_account

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

type MCMSAccountInterface interface {
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsSelfOwned(opts *bind.CallOpts) (bool, error)

	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnershipToSelf(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_account","name":"accept_ownership","parameters":null},{"package":"mcms","module":"mcms_account","name":"assert_is_owner","parameters":null},{"package":"mcms","module":"mcms_account","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"mcms","module":"mcms_account","name":"transfer_ownership_to_self","parameters":null}]`

// Structs

type AccountState struct {
	Owner        aptos.AccountAddress `move:"address"`
	PendingOwner aptos.AccountAddress `move:"address"`
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferred struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type MCMSAccount struct {
	MCMSAccountCaller
	MCMSAccountTransactor
}

// View Functions

type MCMSAccountCaller struct {
	*bind.BoundContract
}

func (c MCMSAccountCaller) EncodeOwner() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c MCMSAccountCaller) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
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

func (c MCMSAccountCaller) EncodeIsSelfOwned() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_self_owned", nil, []string{}, []any{})
}

func (c MCMSAccountCaller) IsSelfOwned(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.EncodeIsSelfOwned()
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

// Entry Functions

type MCMSAccountTransactor struct {
	*bind.BoundContract
}

func (c MCMSAccountTransactor) EncodeTransferOwnership(to aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c MCMSAccountTransactor) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeTransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSAccountTransactor) EncodeTransferOwnershipToSelf() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership_to_self", nil, []string{}, []any{})
}

func (c MCMSAccountTransactor) TransferOwnershipToSelf(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeTransferOwnershipToSelf()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c MCMSAccountCaller) EncodeAcceptOwnership() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c MCMSAccountCaller) EncodeAssertIsOwner() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_owner", nil, []string{}, []any{})
}
