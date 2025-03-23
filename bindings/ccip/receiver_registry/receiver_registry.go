// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_receiver_registry

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

type ReceiverRegistryInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)

	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"ccip","module":"receiver_registry","name":"finish_receive","parameters":[{"name":"receiver_address","type":"address"}]},{"package":"ccip","module":"receiver_registry","name":"initialize","parameters":null}]`

// Structs

type ReceiverRegistryState struct {
}

type CCIPReceiverRegistration struct {
}

type ReceiverRegistered struct {
	ReceiverAddress    aptos.AccountAddress `move:"address"`
	ReceiverModuleName []byte               `move:"vector<u8>"`
}

type McmsCallback struct {
}

type ReceiverRegistry struct {
	ReceiverRegistryCaller
	ReceiverRegistryTransactor
}

// View Functions

type ReceiverRegistryCaller struct {
	*bind.BoundContract
}

func (c ReceiverRegistryCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c ReceiverRegistryCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.EncodeTypeAndVersion()
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

// Entry Functions

type ReceiverRegistryTransactor struct {
	*bind.BoundContract
}

func (c ReceiverRegistryTransactor) EncodeInitialize() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{}, []any{})
}

func (c ReceiverRegistryTransactor) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeInitialize()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c ReceiverRegistryCaller) EncodeFinishReceive(receiverAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_receive", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}
