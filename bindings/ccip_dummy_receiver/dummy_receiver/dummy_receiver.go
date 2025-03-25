// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_dummy_receiver

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

type DummyReceiver interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
}

const FunctionInfo = `null`

// Structs

type ReceivedMessage struct {
	Data []byte `move:"vector<u8>"`
}

type DummyReceiverProof struct {
}

type DummyReceiverContract struct {
	DummyReceiverCaller
	DummyReceiverTransactor
}

// View Functions

type DummyReceiverCaller struct {
	*bind.BoundContract
}

func (c DummyReceiverCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c DummyReceiverCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
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

type DummyReceiverTransactor struct {
	*bind.BoundContract
}
