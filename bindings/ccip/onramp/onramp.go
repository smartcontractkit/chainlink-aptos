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

type Onramp interface {
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

	Encode_() OnrampEncoder
}

type OnrampEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetExpectedNextSequenceNumber(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChainConfig(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedSendersList(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDynamicConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetDynamicConfig(allowlistAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowlistUpdates(destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"onramp","name":"apply_allowlist_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_add_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"},{"name":"dest_chain_remove_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"}]},{"package":"ccip","module":"onramp","name":"apply_dest_chain_config_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip","module":"onramp","name":"ccip_send","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"onramp","name":"initialize","parameters":[{"name":"chain_selector","type":"u64"},{"name":"allowlist_admin","type":"address"},{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip","module":"onramp","name":"set_dynamic_config","parameters":[{"name":"allowlist_admin","type":"address"}]}]`

func NewOnramp(address aptos.AccountAddress, client aptos.AptosRpcClient) Onramp {
	contract := bind.NewBoundContract(address, "ccip", "onramp", client)
	return OnrampContract{
		BoundContract: contract,
		onrampEncoder: onrampEncoder{BoundContract: contract},
	}
}

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

type OnrampContract struct {
	*bind.BoundContract
	onrampEncoder
}

var _ Onramp = OnrampContract{}

func (c OnrampContract) Encode_() OnrampEncoder {
	return c.onrampEncoder
}

// View Functions

func (c OnrampContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.onrampEncoder.TypeAndVersion()
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

func (c OnrampContract) IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.onrampEncoder.IsChainSupported(destChainSelector)
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

func (c OnrampContract) GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetExpectedNextSequenceNumber(destChainSelector)
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

func (c OnrampContract) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetFee(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
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

func (c OnrampContract) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (bool, uint64, bool, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetDestChainConfig(destChainSelector)
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

func (c OnrampContract) GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetAllowedSendersList(destChainSelector)
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

func (c OnrampContract) GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetOutboundNonce(destChainSelector, sender)
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

func (c OnrampContract) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetStaticConfig()
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

func (c OnrampContract) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetDynamicConfig()
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

func (c OnrampContract) Initialize(opts *bind.TransactOpts, chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.Initialize(chainSelector, allowlistAdmin, destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) SetDynamicConfig(opts *bind.TransactOpts, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.SetDynamicConfig(allowlistAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.ApplyDestChainConfigUpdates(destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.ApplyAllowlistUpdates(destChainSelectors, destChainAllowlistEnabled, destChainAddAllowedSenders, destChainRemoveAllowedSenders)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type onrampEncoder struct {
	*bind.BoundContract
}

func (c onrampEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c onrampEncoder) IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_chain_supported", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c onrampEncoder) GetExpectedNextSequenceNumber(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_expected_next_sequence_number", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c onrampEncoder) GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c onrampEncoder) GetDestChainConfig(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chain_config", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c onrampEncoder) GetAllowedSendersList(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_senders_list", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c onrampEncoder) GetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_outbound_nonce", nil, []string{
		"u64",
		"address",
	}, []any{
		destChainSelector,
		sender,
	})
}

func (c onrampEncoder) GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_static_config", nil, []string{}, []any{})
}

func (c onrampEncoder) GetDynamicConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dynamic_config", nil, []string{}, []any{})
}

func (c onrampEncoder) Initialize(chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c onrampEncoder) SetDynamicConfig(allowlistAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_dynamic_config", nil, []string{
		"address",
	}, []any{
		allowlistAdmin,
	})
}

func (c onrampEncoder) ApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c onrampEncoder) ApplyAllowlistUpdates(destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c onrampEncoder) CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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
