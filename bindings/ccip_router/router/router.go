// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_router

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

type Router interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)

	CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error)

	// Encode returns the encoder implementation of this module.
	Encoder() RouterEncoder
}

type RouterEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSendWithMessageId(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_router","module":"router","name":"ccip_send","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip_router","module":"router","name":"ccip_send_with_message_id","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]}]`

func NewRouter(address aptos.AccountAddress, client aptos.AptosRpcClient) Router {
	contract := bind.NewBoundContract(address, "ccip_router", "router", client)
	return RouterContract{
		BoundContract: contract,
		routerEncoder: routerEncoder{BoundContract: contract},
	}
}

// Structs

type RouterState struct {
}

type RouterContract struct {
	*bind.BoundContract
	routerEncoder
}

var _ Router = RouterContract{}

func (c RouterContract) Encoder() RouterEncoder {
	return c.routerEncoder
}

// View Functions

func (c RouterContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.routerEncoder.TypeAndVersion()
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

func (c RouterContract) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetStateAddress()
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

func (c RouterContract) IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.routerEncoder.IsChainSupported(destChainSelector)
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

func (c RouterContract) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetFee(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
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

func (c RouterContract) CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.CCIPSend(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type routerEncoder struct {
	*bind.BoundContract
}

func (c routerEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c routerEncoder) GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address", nil, []string{}, []any{})
}

func (c routerEncoder) IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_chain_supported", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c routerEncoder) GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_fee", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}

func (c routerEncoder) CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ccip_send", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}

func (c routerEncoder) CCIPSendWithMessageId(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ccip_send_with_message_id", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}
