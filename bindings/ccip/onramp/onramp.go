// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_onramp

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

type OnrampInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error)
	GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)
	GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (bool, uint64, bool, error)
	GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error)
	GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"ccip","module":"onramp","name":"apply_allowlist_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_add_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"},{"name":"dest_chain_remove_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"}]},{"package":"ccip","module":"onramp","name":"apply_dest_chain_config_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip","module":"onramp","name":"ccip_send","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"onramp","name":"initialize","parameters":[{"name":"chain_selector","type":"u64"},{"name":"allowlist_admin","type":"address"},{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip","module":"onramp","name":"set_dynamic_config","parameters":[{"name":"allowlist_admin","type":"address"}]}]`

// Structs

type OnRampState struct {
	ChainSelector  uint64               `move:"u64"`
	AllowlistAdmin aptos.AccountAddress `move:"address"`
}

type DestChainConfig struct {
	IsEnabled        bool                   `move:"bool"`
	SequenceNumber   uint64                 `move:"u64"`
	AllowlistEnabled bool                   `move:"bool"`
	AllowedSenders   []aptos.AccountAddress `move:"vector<address>"`
}

type RampMessageHeader struct {
	MessageId           []byte `move:"vector<u8>"`
	SourceChainSelector uint64 `move:"u64"`
	DestChainSelector   uint64 `move:"u64"`
	SequenceNumber      uint64 `move:"u64"`
	Nonce               uint64 `move:"u64"`
}

type Aptos2AnyRampMessage struct {
	Header         RampMessageHeader        `move:"RampMessageHeader"`
	Sender         aptos.AccountAddress     `move:"address"`
	Data           []byte                   `move:"vector<u8>"`
	Receiver       []byte                   `move:"vector<u8>"`
	ExtraArgs      []byte                   `move:"vector<u8>"`
	FeeToken       aptos.AccountAddress     `move:"address"`
	FeeTokenAmount uint64                   `move:"u64"`
	FeeValueJuels  uint64                   `move:"u64"`
	TokenAmounts   []Aptos2AnyTokenTransfer `move:"vector<Aptos2AnyTokenTransfer>"`
}

type Aptos2AnyTokenTransfer struct {
	SourcePoolAddress aptos.AccountAddress `move:"address"`
	DestTokenAddress  []byte               `move:"vector<u8>"`
	ExtraData         []byte               `move:"vector<u8>"`
	Amount            uint64               `move:"u64"`
	DestExecData      []byte               `move:"vector<u8>"`
}

type StaticConfig struct {
	ChainSelector uint64 `move:"u64"`
}

type DynamicConfig struct {
	AllowlistAdmin aptos.AccountAddress `move:"address"`
}

type ConfigSet struct {
	ChainSelector  uint64               `move:"u64"`
	AllowlistAdmin aptos.AccountAddress `move:"address"`
}

type DestChainConfigSet struct {
	DestChainSelector uint64 `move:"u64"`
	IsEnabled         bool   `move:"bool"`
	SequenceNumber    uint64 `move:"u64"`
	AllowlistEnabled  bool   `move:"bool"`
}

type CCIPMessageSent struct {
	DestChainSelector uint64               `move:"u64"`
	SequenceNumber    uint64               `move:"u64"`
	Message           Aptos2AnyRampMessage `move:"Aptos2AnyRampMessage"`
}

type AllowlistSendersAdded struct {
	DestChainSelector uint64                 `move:"u64"`
	Senders           []aptos.AccountAddress `move:"vector<address>"`
}

type AllowlistSendersRemoved struct {
	DestChainSelector uint64                 `move:"u64"`
	Senders           []aptos.AccountAddress `move:"vector<address>"`
}

type McmsCallback struct {
}

type Onramp struct {
	OnrampCaller
	OnrampTransactor
}

// View Functions

type OnrampCaller struct {
	*bind.BoundContract
}

func (c OnrampCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c OnrampCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
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

func (c OnrampCaller) EncodeIsChainSupported(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_chain_supported", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c OnrampCaller) IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error) {
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

func (c OnrampCaller) EncodeGetExpectedNextSequenceNumber(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_expected_next_sequence_number", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c OnrampCaller) GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetExpectedNextSequenceNumber(destChainSelector)
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

func (c OnrampCaller) EncodeGetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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

func (c OnrampCaller) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
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

func (c OnrampCaller) EncodeGetDestChainConfig(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chain_config", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c OnrampCaller) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (bool, uint64, bool, error) {
	module, function, typeTags, args, err := c.EncodeGetDestChainConfig(destChainSelector)
	if err != nil {
		return *new(bool), *new(uint64), *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), *new(uint64), *new(bool), err
	}

	var (
		r0 bool
		r1 uint64
		r2 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new(bool), *new(uint64), *new(bool), err
	}
	return r0, r1, r2, nil
}

func (c OnrampCaller) EncodeGetAllowedSendersList(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_senders_list", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c OnrampCaller) GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeGetAllowedSendersList(destChainSelector)
	if err != nil {
		return *new(bool), *new([]aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), *new([]aptos.AccountAddress), err
	}

	var (
		r0 bool
		r1 []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1); err != nil {
		return *new(bool), *new([]aptos.AccountAddress), err
	}
	return r0, r1, nil
}

func (c OnrampCaller) EncodeGetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_outbound_nonce", nil, []string{
		"u64",
		"address",
	}, []any{
		destChainSelector,
		sender,
	})
}

func (c OnrampCaller) GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetOutboundNonce(destChainSelector, sender)
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

func (c OnrampCaller) EncodeGetStaticConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_static_config", nil, []string{}, []any{})
}

func (c OnrampCaller) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := c.EncodeGetStaticConfig()
	if err != nil {
		return *new(StaticConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(StaticConfig), err
	}

	var (
		r0 StaticConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(StaticConfig), err
	}
	return r0, nil
}

func (c OnrampCaller) EncodeGetDynamicConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dynamic_config", nil, []string{}, []any{})
}

func (c OnrampCaller) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := c.EncodeGetDynamicConfig()
	if err != nil {
		return *new(DynamicConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(DynamicConfig), err
	}

	var (
		r0 DynamicConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(DynamicConfig), err
	}
	return r0, nil
}

// Entry Functions

type OnrampTransactor struct {
	*bind.BoundContract
}

func (c OnrampTransactor) EncodeInitialize(chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
		"address",
		"vector<u64>",
		"vector<bool>",
		"vector<bool>",
	}, []any{
		chainSelector,
		allowlistAdmin,
		destChainSelectors,
		destChainEnabled,
		destChainAllowlistEnabled,
	})
}

func (c OnrampTransactor) Initialize(opts *bind.TransactOpts, chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeInitialize(chainSelector, allowlistAdmin, destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampTransactor) EncodeSetDynamicConfig(allowlistAdmin aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_dynamic_config", nil, []string{
		"address",
	}, []any{
		allowlistAdmin,
	})
}

func (c OnrampTransactor) SetDynamicConfig(opts *bind.TransactOpts, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeSetDynamicConfig(allowlistAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampTransactor) EncodeApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_dest_chain_config_updates", nil, []string{
		"vector<u64>",
		"vector<bool>",
		"vector<bool>",
	}, []any{
		destChainSelectors,
		destChainEnabled,
		destChainAllowlistEnabled,
	})
}

func (c OnrampTransactor) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeApplyDestChainConfigUpdates(destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampTransactor) EncodeApplyAllowlistUpdates(destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowlist_updates", nil, []string{
		"vector<u64>",
		"vector<bool>",
		"vector<vector<address>>",
		"vector<vector<address>>",
	}, []any{
		destChainSelectors,
		destChainAllowlistEnabled,
		destChainAddAllowedSenders,
		destChainRemoveAllowedSenders,
	})
}

func (c OnrampTransactor) ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeApplyAllowlistUpdates(destChainSelectors, destChainAllowlistEnabled, destChainAddAllowedSenders, destChainRemoveAllowedSenders)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c OnrampCaller) EncodeCCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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
