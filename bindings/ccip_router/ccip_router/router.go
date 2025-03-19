// Code generated - DO NOT EDIT

package module_router

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type RouterInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)

	CcipSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error)
}

// Structs

type RouterState struct {
}

type Router struct {
	RouterCaller
	RouterTransactor
}

// View Functions

type RouterCaller struct {
	*bind.BoundContract
}

func (c RouterCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.Encode("type_and_version", nil, []string{}, []any{})
}

func (c RouterCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
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

func (c RouterCaller) EncodeGetStateAddress() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.Encode("get_state_address", nil, []string{}, []any{})
}

func (c RouterCaller) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeGetStateAddress()
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

func (c RouterCaller) EncodeIsChainSupported(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.Encode("is_chain_supported", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c RouterCaller) IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.EncodeIsChainSupported(destChainSelector)
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

func (c RouterCaller) EncodeGetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.Encode("get_fee", nil, []string{
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

func (c RouterCaller) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetFee(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
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

type RouterTransactor struct {
	*bind.BoundContract
}

func (c RouterTransactor) EncodeCcipSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.Encode("ccip_send", nil, []string{
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

func (c RouterTransactor) CcipSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeCcipSend(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return nil, err
	}

	return c.Transact(opts, module, function, typeTags, args)
}
