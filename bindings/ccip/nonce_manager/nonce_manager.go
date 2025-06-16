// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_nonce_manager

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

type NonceManagerInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() NonceManagerEncoder
}

type NonceManagerEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetIncrementedOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"nonce_manager","name":"get_incremented_outbound_nonce","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"sender","type":"address"}]}]`

func NewNonceManager(address aptos.AccountAddress, client aptos.AptosRpcClient) NonceManagerInterface {
	contract := bind.NewBoundContract(address, "ccip", "nonce_manager", client)
	return NonceManagerContract{
		BoundContract:       contract,
		nonceManagerEncoder: nonceManagerEncoder{BoundContract: contract},
	}
}

// Structs

type NonceManagerState struct {
}

type NonceManagerContract struct {
	*bind.BoundContract
	nonceManagerEncoder
}

var _ NonceManagerInterface = NonceManagerContract{}

func (c NonceManagerContract) Encoder() NonceManagerEncoder {
	return c.nonceManagerEncoder
}

// View Functions

func (c NonceManagerContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.nonceManagerEncoder.TypeAndVersion()
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

func (c NonceManagerContract) GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := c.nonceManagerEncoder.GetOutboundNonce(destChainSelector, sender)
	if err != nil {
		return *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), err
	}

	var (
		r0 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(uint64), err
	}
	return r0, nil
}

// Entry Functions

// Encoder
type nonceManagerEncoder struct {
	*bind.BoundContract
}

func (c nonceManagerEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c nonceManagerEncoder) GetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_outbound_nonce", nil, []string{
		"u64",
		"address",
	}, []any{
		destChainSelector,
		sender,
	})
}

func (c nonceManagerEncoder) GetIncrementedOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_incremented_outbound_nonce", nil, []string{
		"u64",
		"address",
	}, []any{
		destChainSelector,
		sender,
	})
}
