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
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSAccountEncoder
}

type MCMSAccountEncoder interface {
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsSelfOwned() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnershipToSelf() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_account","name":"accept_ownership","parameters":null},{"package":"mcms","module":"mcms_account","name":"assert_is_owner","parameters":null},{"package":"mcms","module":"mcms_account","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"mcms","module":"mcms_account","name":"transfer_ownership_to_self","parameters":null}]`

func NewMCMSAccount(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSAccountInterface {
	contract := bind.NewBoundContract(address, "mcms", "mcms_account", client)
	return MCMSAccountContract{
		BoundContract:      contract,
		mcmsAccountEncoder: mcmsAccountEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_CANNOT_TRANSFER_TO_SELF uint64 = 1
	E_MUST_BE_PROPOSED_OWNER  uint64 = 2
	E_UNAUTHORIZED            uint64 = 3
)

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

type MCMSAccountContract struct {
	*bind.BoundContract
	mcmsAccountEncoder
}

var _ MCMSAccountInterface = MCMSAccountContract{}

func (c MCMSAccountContract) Encoder() MCMSAccountEncoder {
	return c.mcmsAccountEncoder
}

// View Functions

func (c MCMSAccountContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsAccountEncoder.Owner()
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

func (c MCMSAccountContract) IsSelfOwned(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.mcmsAccountEncoder.IsSelfOwned()
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

func (c MCMSAccountContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsAccountEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSAccountContract) TransferOwnershipToSelf(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsAccountEncoder.TransferOwnershipToSelf()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSAccountContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsAccountEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsAccountEncoder struct {
	*bind.BoundContract
}

func (c mcmsAccountEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c mcmsAccountEncoder) IsSelfOwned() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_self_owned", nil, []string{}, []any{})
}

func (c mcmsAccountEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c mcmsAccountEncoder) TransferOwnershipToSelf() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership_to_self", nil, []string{}, []any{})
}

func (c mcmsAccountEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c mcmsAccountEncoder) AssertIsOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_owner", nil, []string{}, []any{})
}
