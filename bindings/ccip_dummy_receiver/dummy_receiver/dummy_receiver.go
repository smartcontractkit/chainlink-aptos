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

type DummyReceiverInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() DummyReceiverEncoder
}

type DummyReceiverEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPReceive(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_dummy_receiver","module":"dummy_receiver","name":"ccip_receive","parameters":[{"name":"_metadata","type":"address"}]}]`

func NewDummyReceiver(address aptos.AccountAddress, client aptos.AptosRpcClient) DummyReceiverInterface {
	contract := bind.NewBoundContract(address, "ccip_dummy_receiver", "dummy_receiver", client)
	return DummyReceiverContract{
		BoundContract:        contract,
		dummyReceiverEncoder: dummyReceiverEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_TEST_ABORT uint64 = 1
)

// Structs

type ReceivedMessage struct {
	Data []byte `move:"vector<u8>"`
}

type CCIPReceiverState struct {
}

type DummyReceiverProof struct {
}

type DummyReceiverContract struct {
	*bind.BoundContract
	dummyReceiverEncoder
}

var _ DummyReceiverInterface = DummyReceiverContract{}

func (c DummyReceiverContract) Encoder() DummyReceiverEncoder {
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

func (c dummyReceiverEncoder) CCIPReceive(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ccip_receive", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
