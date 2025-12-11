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
	IsRegisteredReceiver(opts *bind.CallOpts, receiverAddress aptos.AccountAddress) (bool, error)
	IsRegisteredReceiverV2(opts *bind.CallOpts, receiverAddress aptos.AccountAddress) (bool, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() ReceiverRegistryEncoder
}

type ReceiverRegistryEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsRegisteredReceiver(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsRegisteredReceiverV2(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishReceive(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"receiver_registry","name":"finish_receive","parameters":[{"name":"receiver_address","type":"address"}]}]`

func NewReceiverRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) ReceiverRegistryInterface {
	contract := bind.NewBoundContract(address, "ccip", "receiver_registry", client)
	return ReceiverRegistryContract{
		BoundContract:           contract,
		receiverRegistryEncoder: receiverRegistryEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_ALREADY_REGISTERED          uint64 = 1
	E_UNKNOWN_RECEIVER            uint64 = 2
	E_UNKNOWN_PROOF_TYPE          uint64 = 3
	E_MISSING_INPUT               uint64 = 4
	E_NON_EMPTY_INPUT             uint64 = 5
	E_PROOF_TYPE_ACCOUNT_MISMATCH uint64 = 6
	E_PROOF_TYPE_MODULE_MISMATCH  uint64 = 7
	E_UNAUTHORIZED                uint64 = 8
)

// Structs

type ReceiverRegistryState struct {
}

type ReceiverRegistryEventsV2 struct {
}

type CCIPReceiverRegistration struct {
	DispatchMetadata bind.StdObject `move:"aptos_framework::object::Object"`
}

type CCIPReceiverRegistrationV2 struct {
}

type ReceiverRegistered struct {
	ReceiverAddress    aptos.AccountAddress `move:"address"`
	ReceiverModuleName []byte               `move:"vector<u8>"`
}

type ReceiverRegisteredV2 struct {
	ReceiverAddress aptos.AccountAddress `move:"address"`
}

type ReceiverRegistryContract struct {
	*bind.BoundContract
	receiverRegistryEncoder
}

var _ ReceiverRegistryInterface = ReceiverRegistryContract{}

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

func (c ReceiverRegistryContract) IsRegisteredReceiver(opts *bind.CallOpts, receiverAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.receiverRegistryEncoder.IsRegisteredReceiver(receiverAddress)
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

func (c ReceiverRegistryContract) IsRegisteredReceiverV2(opts *bind.CallOpts, receiverAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.receiverRegistryEncoder.IsRegisteredReceiverV2(receiverAddress)
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

// Encoder
type receiverRegistryEncoder struct {
	*bind.BoundContract
}

func (c receiverRegistryEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c receiverRegistryEncoder) IsRegisteredReceiver(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_registered_receiver", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}

func (c receiverRegistryEncoder) IsRegisteredReceiverV2(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_registered_receiver_v2", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}

func (c receiverRegistryEncoder) FinishReceive(receiverAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_receive", nil, []string{
		"address",
	}, []any{
		receiverAddress,
	})
}
