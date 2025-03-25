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

	EncodeCall() DummyReceiverEncoder
}

type DummyReceiverEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `null`

func NewDummyReceiver(address aptos.AccountAddress, client aptos.AptosRpcClient) DummyReceiver {
	contract := bind.NewBoundContract(address, "ccip_dummy_receiver", "dummy_receiver", client)
	return DummyReceiverContract{
		BoundContract:        contract,
		dummyReceiverEncoder: dummyReceiverEncoder{BoundContract: contract},
	}
}

// Structs

type ReceivedMessage struct {
	Data []byte `move:"vector<u8>"`
}

type DummyReceiverProof struct {
}

type DummyReceiverContract struct {
	*bind.BoundContract
	dummyReceiverEncoder
}

var _ DummyReceiver = DummyReceiverContract{}

func (c DummyReceiverContract) EncodeCall() DummyReceiverEncoder {
	return c.dummyReceiverEncoder
}

// View Functions

func (c DummyReceiverContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.dummyReceiverEncoder.TypeAndVersion()
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

// Encoder
type dummyReceiverEncoder struct {
	*bind.BoundContract
}

func (c dummyReceiverEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}
