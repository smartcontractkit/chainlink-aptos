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

type ReceiverRegistry interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
}

const FunctionInfo = `[{"package":"ccip","module":"receiver_registry","name":"finish_receive","parameters":[{"name":"receiver_address","type":"address"}]}]`

// Structs

type ReceiverRegistryState struct {
}

type CCIPReceiverRegistration struct {
}

type ReceiverRegistered struct {
	ReceiverAddress    aptos.AccountAddress `move:"address"`
	ReceiverModuleName []byte               `move:"vector<u8>"`
}

type ReceiverRegistryContract struct {
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

// Other Functions

func (c ReceiverRegistryCaller) EncodeFinishReceive(receiverAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_receive", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}
