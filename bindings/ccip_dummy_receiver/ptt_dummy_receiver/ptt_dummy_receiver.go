// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_ptt_dummy_receiver

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

type PttDummyReceiverInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)

	WithdrawToken(opts *bind.TransactOpts, recipient aptos.AccountAddress, tokenAddress aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() PttDummyReceiverEncoder
}

type PttDummyReceiverEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	WithdrawToken(recipient aptos.AccountAddress, tokenAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_dummy_receiver","module":"ptt_dummy_receiver","name":"withdraw_token","parameters":[{"name":"recipient","type":"address"},{"name":"token_address","type":"address"}]}]`

func NewPttDummyReceiver(address aptos.AccountAddress, client aptos.AptosRpcClient) PttDummyReceiverInterface {
	contract := bind.NewBoundContract(address, "ccip_dummy_receiver", "ptt_dummy_receiver", client)
	return PttDummyReceiverContract{
		BoundContract:           contract,
		pttDummyReceiverEncoder: pttDummyReceiverEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_RESOURCE_NOT_FOUND_ON_ACCOUNT   uint64 = 1
	E_UNAUTHORIZED                    uint64 = 2
	E_NO_TOKENS_AVAILABLE_TO_WITHDRAW uint64 = 3
	E_TEST_ABORT                      uint64 = 4
)

// Structs

type ReceivedMessage struct {
	Data []byte `move:"vector<u8>"`
}

type CCIPReceiverState struct {
}

type PttDummyReceiverContract struct {
	*bind.BoundContract
	pttDummyReceiverEncoder
}

var _ PttDummyReceiverInterface = PttDummyReceiverContract{}

func (c PttDummyReceiverContract) Encoder() PttDummyReceiverEncoder {
	return c.pttDummyReceiverEncoder
}

// View Functions

func (c PttDummyReceiverContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.pttDummyReceiverEncoder.TypeAndVersion()
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

func (c PttDummyReceiverContract) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.pttDummyReceiverEncoder.GetStateAddress()
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

func (c PttDummyReceiverContract) WithdrawToken(opts *bind.TransactOpts, recipient aptos.AccountAddress, tokenAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.pttDummyReceiverEncoder.WithdrawToken(recipient, tokenAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type pttDummyReceiverEncoder struct {
	*bind.BoundContract
}

func (c pttDummyReceiverEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c pttDummyReceiverEncoder) GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address", nil, []string{}, []any{})
}

func (c pttDummyReceiverEncoder) WithdrawToken(recipient aptos.AccountAddress, tokenAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("withdraw_token", nil, []string{
		"address",
		"address",
	}, []any{
		recipient,
		tokenAddress,
	})
}
