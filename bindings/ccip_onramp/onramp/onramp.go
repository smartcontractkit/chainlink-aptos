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
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error)
	GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)
	GetDestChainConfigV2(opts *bind.CallOpts, destChainSelector uint64) (uint64, bool, aptos.AccountAddress, aptos.AccountAddress, error)
	GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (uint64, bool, aptos.AccountAddress, error)
	GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error)
	GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)
	DestChainConfigsV2Exists(opts *bind.CallOpts) (bool, error)
	CalculateMetadataHash(opts *bind.CallOpts, sourceChainSelector uint64, destChainSelector uint64) ([]byte, error)
	CalculateMessageHash(opts *bind.CallOpts, messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender aptos.AccountAddress, receiver []byte, data []byte, feeToken aptos.AccountAddress, feeTokenAmount uint64, sourcePoolAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, extraDatas [][]byte, amounts []uint64, destExecDatas [][]byte, extraArgs []byte) ([]byte, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdatesV2(opts *bind.TransactOpts, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainRouterStateAddresses []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error)
	WithdrawFeeTokens(opts *bind.TransactOpts, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	MigrateDestChainConfigsToV2(opts *bind.TransactOpts, destChainSelectors []uint64, routerModuleAddresses []aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() OnrampEncoder
}

type OnrampEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetExpectedNextSequenceNumber(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChainConfigV2(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChainConfig(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedSendersList(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDynamicConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DestChainConfigsV2Exists() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMetadataHash(sourceChainSelector uint64, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMessageHash(messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender aptos.AccountAddress, receiver []byte, data []byte, feeToken aptos.AccountAddress, feeTokenAmount uint64, sourcePoolAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, extraDatas [][]byte, amounts []uint64, destExecDatas [][]byte, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(chainSelector uint64, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetDynamicConfig(feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyDestChainConfigUpdatesV2(destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainRouterStateAddresses []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowlistUpdates(destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	WithdrawFeeTokens(feeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MigrateDestChainConfigsToV2(destChainSelectors []uint64, routerModuleAddresses []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFeeInternal(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ResolveFungibleAsset(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ResolveFungibleStore(owner aptos.AccountAddress, token aptos.AccountAddress, storeAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMetadataHashInlined(sourceChainSelector uint64, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_onramp","module":"onramp","name":"accept_ownership","parameters":null},{"package":"ccip_onramp","module":"onramp","name":"apply_allowlist_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"},{"name":"dest_chain_add_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"},{"name":"dest_chain_remove_allowed_senders","type":"vector\u003cvector\u003caddress\u003e\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"apply_dest_chain_config_updates","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_routers","type":"vector\u003caddress\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"apply_dest_chain_config_updates_v2","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_routers","type":"vector\u003caddress\u003e"},{"name":"dest_chain_router_state_addresses","type":"vector\u003caddress\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"calculate_metadata_hash_inlined","parameters":[{"name":"source_chain_selector","type":"u64"},{"name":"dest_chain_selector","type":"u64"}]},{"package":"ccip_onramp","module":"onramp","name":"ccip_send","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"get_fee_internal","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"get_state_address_internal","parameters":null},{"package":"ccip_onramp","module":"onramp","name":"initialize","parameters":[{"name":"chain_selector","type":"u64"},{"name":"fee_aggregator","type":"address"},{"name":"allowlist_admin","type":"address"},{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"dest_chain_routers","type":"vector\u003caddress\u003e"},{"name":"dest_chain_allowlist_enabled","type":"vector\u003cbool\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"migrate_dest_chain_configs_to_v2","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"router_module_addresses","type":"vector\u003caddress\u003e"}]},{"package":"ccip_onramp","module":"onramp","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip_onramp","module":"onramp","name":"resolve_fungible_asset","parameters":[{"name":"token","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"resolve_fungible_store","parameters":[{"name":"owner","type":"address"},{"name":"token","type":"address"},{"name":"store_address","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"set_dynamic_config","parameters":[{"name":"fee_aggregator","type":"address"},{"name":"allowlist_admin","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"ccip_onramp","module":"onramp","name":"withdraw_fee_tokens","parameters":[{"name":"fee_tokens","type":"vector\u003caddress\u003e"}]}]`

func NewOnramp(address aptos.AccountAddress, client aptos.AptosRpcClient) OnrampInterface {
	contract := bind.NewBoundContract(address, "ccip_onramp", "onramp", client)
	return OnrampContract{
		BoundContract: contract,
		onrampEncoder: onrampEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_ALREADY_INITIALIZED                       uint64 = 1
	E_DEST_CHAIN_ARGUMENT_MISMATCH              uint64 = 2
	E_INVALID_DEST_CHAIN_SELECTOR               uint64 = 3
	E_UNKNOWN_DEST_CHAIN_SELECTOR               uint64 = 4
	E_UNKNOWN_FUNCTION                          uint64 = 5
	E_SENDER_NOT_ALLOWED                        uint64 = 6
	E_ONLY_CALLABLE_BY_OWNER_OR_ALLOWLIST_ADMIN uint64 = 7
	E_INVALID_ALLOWLIST_REQUEST                 uint64 = 8
	E_INVALID_ALLOWLIST_ADDRESS                 uint64 = 9
	E_UNSUPPORTED_TOKEN                         uint64 = 10
	E_INVALID_FEE_TOKEN                         uint64 = 11
	E_CURSED_BY_RMN                             uint64 = 12
	E_INVALID_TOKEN                             uint64 = 13
	E_INVALID_TOKEN_STORE                       uint64 = 14
	E_UNEXPECTED_WITHDRAW_AMOUNT                uint64 = 15
	E_UNEXPECTED_FUNGIBLE_ASSET                 uint64 = 16
	E_FEE_AGGREGATOR_NOT_SET                    uint64 = 17
	E_MUST_BE_CALLED_BY_ROUTER                  uint64 = 18
	E_TOKEN_AMOUNT_MISMATCH                     uint64 = 19
	E_CANNOT_SEND_ZERO_TOKENS                   uint64 = 20
	E_ZERO_CHAIN_SELECTOR                       uint64 = 21
	E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS  uint64 = 22
	E_DEST_CHAIN_CONFIGS_V2_ALREADY_INITIALIZED uint64 = 23
	E_DEST_CHAIN_CONFIGS_V2_NOT_INITIALIZED     uint64 = 24
)

// Structs

type OnRampDeployment struct {
}

type OnRampState struct {
	ChainSelector  uint64               `move:"u64"`
	FeeAggregator  aptos.AccountAddress `move:"address"`
	AllowlistAdmin aptos.AccountAddress `move:"address"`
}

type DestChainConfigsV2 struct {
}

type DestChainConfig struct {
	SequenceNumber   uint64                 `move:"u64"`
	AllowlistEnabled bool                   `move:"bool"`
	Router           aptos.AccountAddress   `move:"address"`
	AllowedSenders   []aptos.AccountAddress `move:"vector<address>"`
}

type DestChainConfigV2 struct {
	SequenceNumber     uint64                 `move:"u64"`
	AllowlistEnabled   bool                   `move:"bool"`
	Router             aptos.AccountAddress   `move:"address"`
	RouterStateAddress aptos.AccountAddress   `move:"address"`
	AllowedSenders     []aptos.AccountAddress `move:"vector<address>"`
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
	FeeValueJuels  *big.Int                 `move:"u256"`
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
	FeeAggregator  aptos.AccountAddress `move:"address"`
	AllowlistAdmin aptos.AccountAddress `move:"address"`
}

type ConfigSet struct {
	StaticConfig  StaticConfig  `move:"StaticConfig"`
	DynamicConfig DynamicConfig `move:"DynamicConfig"`
}

type DestChainConfigSet struct {
	DestChainSelector uint64               `move:"u64"`
	SequenceNumber    uint64               `move:"u64"`
	Router            aptos.AccountAddress `move:"address"`
	AllowlistEnabled  bool                 `move:"bool"`
}

type DestChainConfigSetV2 struct {
	DestChainSelector  uint64               `move:"u64"`
	SequenceNumber     uint64               `move:"u64"`
	Router             aptos.AccountAddress `move:"address"`
	RouterStateAddress aptos.AccountAddress `move:"address"`
	AllowlistEnabled   bool                 `move:"bool"`
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

type FeeTokenWithdrawn struct {
	FeeAggregator aptos.AccountAddress `move:"address"`
	FeeToken      aptos.AccountAddress `move:"address"`
	Amount        uint64               `move:"u64"`
}

type McmsCallback struct {
}

type OnrampContract struct {
	*bind.BoundContract
	onrampEncoder
}

var _ OnrampInterface = OnrampContract{}

func (c OnrampContract) Encoder() OnrampEncoder {
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

func (c OnrampContract) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetStateAddress()
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

func (c OnrampContract) GetDestChainConfigV2(opts *bind.CallOpts, destChainSelector uint64) (uint64, bool, aptos.AccountAddress, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetDestChainConfigV2(destChainSelector)
	if err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}

	var (
		r0 uint64
		r1 bool
		r2 aptos.AccountAddress
		r3 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2, &r3); err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}
	return r0, r1, r2, r3, nil
}

func (c OnrampContract) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (uint64, bool, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.GetDestChainConfig(destChainSelector)
	if err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), err
	}

	var (
		r0 uint64
		r1 bool
		r2 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new(uint64), *new(bool), *new(aptos.AccountAddress), err
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

func (c OnrampContract) DestChainConfigsV2Exists(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.onrampEncoder.DestChainConfigsV2Exists()
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

func (c OnrampContract) CalculateMetadataHash(opts *bind.CallOpts, sourceChainSelector uint64, destChainSelector uint64) ([]byte, error) {
	module, function, typeTags, args, err := c.onrampEncoder.CalculateMetadataHash(sourceChainSelector, destChainSelector)
	if err != nil {
		return *new([]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), err
	}

	var (
		r0 []byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]byte), err
	}
	return r0, nil
}

func (c OnrampContract) CalculateMessageHash(opts *bind.CallOpts, messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender aptos.AccountAddress, receiver []byte, data []byte, feeToken aptos.AccountAddress, feeTokenAmount uint64, sourcePoolAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, extraDatas [][]byte, amounts []uint64, destExecDatas [][]byte, extraArgs []byte) ([]byte, error) {
	module, function, typeTags, args, err := c.onrampEncoder.CalculateMessageHash(messageId, sourceChainSelector, destChainSelector, sequenceNumber, nonce, sender, receiver, data, feeToken, feeTokenAmount, sourcePoolAddresses, destTokenAddresses, extraDatas, amounts, destExecDatas, extraArgs)
	if err != nil {
		return *new([]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), err
	}

	var (
		r0 []byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]byte), err
	}
	return r0, nil
}

func (c OnrampContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.Owner()
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

func (c OnrampContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.onrampEncoder.HasPendingTransfer()
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

func (c OnrampContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.PendingTransferFrom()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c OnrampContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.onrampEncoder.PendingTransferTo()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c OnrampContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.onrampEncoder.PendingTransferAccepted()
	if err != nil {
		return *new(*bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bool), err
	}

	var (
		r0 bind.StdOption[bool]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bool), err
	}
	return r0.Value(), nil
}

// Entry Functions

func (c OnrampContract) Initialize(opts *bind.TransactOpts, chainSelector uint64, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.Initialize(chainSelector, feeAggregator, allowlistAdmin, destChainSelectors, destChainRouters, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) SetDynamicConfig(opts *bind.TransactOpts, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.SetDynamicConfig(feeAggregator, allowlistAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) ApplyDestChainConfigUpdatesV2(opts *bind.TransactOpts, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainRouterStateAddresses []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.ApplyDestChainConfigUpdatesV2(destChainSelectors, destChainRouters, destChainRouterStateAddresses, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.ApplyDestChainConfigUpdates(destChainSelectors, destChainRouters, destChainAllowlistEnabled)
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

func (c OnrampContract) WithdrawFeeTokens(opts *bind.TransactOpts, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.WithdrawFeeTokens(feeTokens)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OnrampContract) MigrateDestChainConfigsToV2(opts *bind.TransactOpts, destChainSelectors []uint64, routerModuleAddresses []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.onrampEncoder.MigrateDestChainConfigsToV2(destChainSelectors, routerModuleAddresses)
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

func (c onrampEncoder) GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address", nil, []string{}, []any{})
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

func (c onrampEncoder) GetDestChainConfigV2(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chain_config_v2", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
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

func (c onrampEncoder) DestChainConfigsV2Exists() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("dest_chain_configs_v2_exists", nil, []string{}, []any{})
}

func (c onrampEncoder) CalculateMetadataHash(sourceChainSelector uint64, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_metadata_hash", nil, []string{
		"u64",
		"u64",
	}, []any{
		sourceChainSelector,
		destChainSelector,
	})
}

func (c onrampEncoder) CalculateMessageHash(messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender aptos.AccountAddress, receiver []byte, data []byte, feeToken aptos.AccountAddress, feeTokenAmount uint64, sourcePoolAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, extraDatas [][]byte, amounts []uint64, destExecDatas [][]byte, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_message_hash", nil, []string{
		"vector<u8>",
		"u64",
		"u64",
		"u64",
		"u64",
		"address",
		"vector<u8>",
		"vector<u8>",
		"address",
		"u64",
		"vector<address>",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
		"vector<u64>",
		"vector<vector<u8>>",
		"vector<u8>",
	}, []any{
		messageId,
		sourceChainSelector,
		destChainSelector,
		sequenceNumber,
		nonce,
		sender,
		receiver,
		data,
		feeToken,
		feeTokenAmount,
		sourcePoolAddresses,
		destTokenAddresses,
		extraDatas,
		amounts,
		destExecDatas,
		extraArgs,
	})
}

func (c onrampEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c onrampEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c onrampEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c onrampEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c onrampEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c onrampEncoder) Initialize(chainSelector uint64, feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
		"address",
		"address",
		"vector<u64>",
		"vector<address>",
		"vector<bool>",
	}, []any{
		chainSelector,
		feeAggregator,
		allowlistAdmin,
		destChainSelectors,
		destChainRouters,
		destChainAllowlistEnabled,
	})
}

func (c onrampEncoder) SetDynamicConfig(feeAggregator aptos.AccountAddress, allowlistAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_dynamic_config", nil, []string{
		"address",
		"address",
	}, []any{
		feeAggregator,
		allowlistAdmin,
	})
}

func (c onrampEncoder) ApplyDestChainConfigUpdatesV2(destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainRouterStateAddresses []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_dest_chain_config_updates_v2", nil, []string{
		"vector<u64>",
		"vector<address>",
		"vector<address>",
		"vector<bool>",
	}, []any{
		destChainSelectors,
		destChainRouters,
		destChainRouterStateAddresses,
		destChainAllowlistEnabled,
	})
}

func (c onrampEncoder) ApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainRouters []aptos.AccountAddress, destChainAllowlistEnabled []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_dest_chain_config_updates", nil, []string{
		"vector<u64>",
		"vector<address>",
		"vector<bool>",
	}, []any{
		destChainSelectors,
		destChainRouters,
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

func (c onrampEncoder) WithdrawFeeTokens(feeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("withdraw_fee_tokens", nil, []string{
		"vector<address>",
	}, []any{
		feeTokens,
	})
}

func (c onrampEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c onrampEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c onrampEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c onrampEncoder) MigrateDestChainConfigsToV2(destChainSelectors []uint64, routerModuleAddresses []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("migrate_dest_chain_configs_to_v2", nil, []string{
		"vector<u64>",
		"vector<address>",
	}, []any{
		destChainSelectors,
		routerModuleAddresses,
	})
}

func (c onrampEncoder) GetFeeInternal(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_fee_internal", nil, []string{
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

func (c onrampEncoder) ResolveFungibleAsset(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("resolve_fungible_asset", nil, []string{
		"address",
	}, []any{
		token,
	})
}

func (c onrampEncoder) ResolveFungibleStore(owner aptos.AccountAddress, token aptos.AccountAddress, storeAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("resolve_fungible_store", nil, []string{
		"address",
		"address",
		"address",
	}, []any{
		owner,
		token,
		storeAddress,
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

func (c onrampEncoder) CalculateMetadataHashInlined(sourceChainSelector uint64, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_metadata_hash_inlined", nil, []string{
		"u64",
		"u64",
	}, []any{
		sourceChainSelector,
		destChainSelector,
	})
}

func (c onrampEncoder) GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address_internal", nil, []string{}, []any{})
}

func (c onrampEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c onrampEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}
