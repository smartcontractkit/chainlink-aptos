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

	// Encoder returns the encoder implementation of this module.
	Encoder() ReceiverRegistryEncoder
}

type ReceiverRegistryEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishReceive(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"receiver_registry","name":"finish_receive","parameters":[{"name":"receiver_address","type":"address"}]}]`

func NewReceiverRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) ReceiverRegistry {
	contract := bind.NewBoundContract(address, "ccip", "receiver_registry", client)
	return ReceiverRegistryContract{
		BoundContract:           contract,
		receiverRegistryEncoder: receiverRegistryEncoder{BoundContract: contract},
	}
}

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
	*bind.BoundContract
	receiverRegistryEncoder
}

var _ ReceiverRegistry = ReceiverRegistryContract{}

func (c ReceiverRegistryContract) Encoder() ReceiverRegistryEncoder {
	return c.receiverRegistryEncoder
}

// View Functions

func (c ReceiverRegistryContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.receiverRegistryEncoder.TypeAndVersion()
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
type receiverRegistryEncoder struct {
	*bind.BoundContract
}

func (c receiverRegistryEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c receiverRegistryEncoder) FinishReceive(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_receive", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}
