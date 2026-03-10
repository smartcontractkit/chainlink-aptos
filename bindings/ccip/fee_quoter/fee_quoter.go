// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_fee_quoter

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

type FeeQuoterInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetTokenPrice(opts *bind.CallOpts, token aptos.AccountAddress) (TimestampedPrice, error)
	GetTokenPrices(opts *bind.CallOpts, tokens []aptos.AccountAddress) ([]TimestampedPrice, error)
	GetDestChainGasPrice(opts *bind.CallOpts, destChainSelector uint64) (TimestampedPrice, error)
	GetTokenAndGasPrices(opts *bind.CallOpts, token aptos.AccountAddress, destChainSelector uint64) (*big.Int, *big.Int, error)
	ConvertTokenAmount(opts *bind.CallOpts, fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (uint64, error)
	GetFeeTokens(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetTokenTransferFeeConfig(opts *bind.CallOpts, destChainSelector uint64, token aptos.AccountAddress) (TokenTransferFeeConfig, error)
	GetValidatedFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, localTokenAddresses []aptos.AccountAddress, localTokenAmounts []uint64, TokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, FeeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)
	GetPremiumMultiplierWeiPerEth(opts *bind.CallOpts, token aptos.AccountAddress) (uint64, error)
	GetTokenReceiver(opts *bind.CallOpts, destChainSelector uint64, extraArgs []byte, messageReceiver []byte) ([]byte, error)
	ProcessMessageArgs(opts *bind.CallOpts, destChainSelector uint64, feeToken aptos.AccountAddress, feeTokenAmount uint64, extraArgs []byte, localTokenAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, destPoolDatas [][]byte) (*big.Int, bool, []byte, [][]byte, error)
	GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (DestChainConfig, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)

	Initialize(opts *bind.TransactOpts, maxFeeJuelsPerMsg *big.Int, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyFeeTokenUpdates(opts *bind.TransactOpts, feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyTokenTransferFeeConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyPremiumMultiplierWeiPerEthUpdates(opts *bind.TransactOpts, tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, isEnabled bool, maxNumberOfTokensPerMsg uint16, maxDataBytes uint32, maxPerMsgGasLimit uint32, destGasOverhead uint32, destGasPerPayloadByteBase byte, destGasPerPayloadByteHigh byte, destGasPerPayloadByteThreshold uint16, destDataAvailabilityOverheadGas uint32, destGasPerDataAvailabilityByte uint16, destDataAvailabilityMultiplierBps uint16, chainFamilySelector []byte, enforceOutOfOrder bool, defaultTokenFeeUsdCents uint16, defaultTokenDestGasOverhead uint32, defaultTxGasLimit uint32, gasMultiplierWeiPerEth uint64, gasPriceStalenessThreshold uint32, networkFeeUsdCents uint32) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() FeeQuoterEncoder
}

type FeeQuoterEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenPrice(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenPrices(tokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChainGasPrice(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenAndGasPrices(token aptos.AccountAddress, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ConvertTokenAmount(fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFeeTokens() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenTransferFeeConfig(destChainSelector uint64, token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetValidatedFee(destChainSelector uint64, receiver []byte, data []byte, localTokenAddresses []aptos.AccountAddress, localTokenAmounts []uint64, TokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, FeeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPremiumMultiplierWeiPerEth(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenReceiver(destChainSelector uint64, extraArgs []byte, messageReceiver []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ProcessMessageArgs(destChainSelector uint64, feeToken aptos.AccountAddress, feeTokenAmount uint64, extraArgs []byte, localTokenAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, destPoolDatas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChainConfig(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(maxFeeJuelsPerMsg *big.Int, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyFeeTokenUpdates(feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyTokenTransferFeeConfigUpdates(destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyPremiumMultiplierWeiPerEthUpdates(tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyDestChainConfigUpdates(destChainSelector uint64, isEnabled bool, maxNumberOfTokensPerMsg uint16, maxDataBytes uint32, maxPerMsgGasLimit uint32, destGasOverhead uint32, destGasPerPayloadByteBase byte, destGasPerPayloadByteHigh byte, destGasPerPayloadByteThreshold uint16, destDataAvailabilityOverheadGas uint32, destGasPerDataAvailabilityByte uint16, destDataAvailabilityMultiplierBps uint16, chainFamilySelector []byte, enforceOutOfOrder bool, defaultTokenFeeUsdCents uint16, defaultTokenDestGasOverhead uint32, defaultTxGasLimit uint32, gasMultiplierWeiPerEth uint64, gasPriceStalenessThreshold uint32, networkFeeUsdCents uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UpdatePrices(sourceTokens []aptos.AccountAddress, sourceUsdPerToken []*big.Int, gasDestChainSelectors []uint64, gasUsdPerUnitGas []*big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DecodeGenericExtraArgsV2(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DecodeSvmExtraArgs(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DecodeSvmExtraArgsV1(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalcUsdValueFromTokenAmount(tokenAmount uint64, tokenPrice *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ValidateDestFamilyAddress(chainFamilySelector []byte, encodedAddress []byte, gasLimit *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ValidateEvmAddress(encodedAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Validate32byteAddress(encodedAddress []byte, minValue *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DestChainConfigValues(config DestChainConfig) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenTransferFeeConfigValues(config TokenTransferFeeConfig) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"fee_quoter","name":"apply_dest_chain_config_updates","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"is_enabled","type":"bool"},{"name":"max_number_of_tokens_per_msg","type":"u16"},{"name":"max_data_bytes","type":"u32"},{"name":"max_per_msg_gas_limit","type":"u32"},{"name":"dest_gas_overhead","type":"u32"},{"name":"dest_gas_per_payload_byte_base","type":"u8"},{"name":"dest_gas_per_payload_byte_high","type":"u8"},{"name":"dest_gas_per_payload_byte_threshold","type":"u16"},{"name":"dest_data_availability_overhead_gas","type":"u32"},{"name":"dest_gas_per_data_availability_byte","type":"u16"},{"name":"dest_data_availability_multiplier_bps","type":"u16"},{"name":"chain_family_selector","type":"vector\u003cu8\u003e"},{"name":"enforce_out_of_order","type":"bool"},{"name":"default_token_fee_usd_cents","type":"u16"},{"name":"default_token_dest_gas_overhead","type":"u32"},{"name":"default_tx_gas_limit","type":"u32"},{"name":"gas_multiplier_wei_per_eth","type":"u64"},{"name":"gas_price_staleness_threshold","type":"u32"},{"name":"network_fee_usd_cents","type":"u32"}]},{"package":"ccip","module":"fee_quoter","name":"apply_fee_token_updates","parameters":[{"name":"fee_tokens_to_remove","type":"vector\u003caddress\u003e"},{"name":"fee_tokens_to_add","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"apply_premium_multiplier_wei_per_eth_updates","parameters":[{"name":"tokens","type":"vector\u003caddress\u003e"},{"name":"premium_multiplier_wei_per_eth","type":"vector\u003cu64\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"apply_token_transfer_fee_config_updates","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"add_tokens","type":"vector\u003caddress\u003e"},{"name":"add_min_fee_usd_cents","type":"vector\u003cu32\u003e"},{"name":"add_max_fee_usd_cents","type":"vector\u003cu32\u003e"},{"name":"add_deci_bps","type":"vector\u003cu16\u003e"},{"name":"add_dest_gas_overhead","type":"vector\u003cu32\u003e"},{"name":"add_dest_bytes_overhead","type":"vector\u003cu32\u003e"},{"name":"add_is_enabled","type":"vector\u003cbool\u003e"},{"name":"remove_tokens","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"calc_usd_value_from_token_amount","parameters":[{"name":"token_amount","type":"u64"},{"name":"token_price","type":"u256"}]},{"package":"ccip","module":"fee_quoter","name":"decode_generic_extra_args_v2","parameters":[{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"decode_svm_extra_args","parameters":[{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"decode_svm_extra_args_v1","parameters":[{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"dest_chain_config_values","parameters":[{"name":"config","type":"DestChainConfig"}]},{"package":"ccip","module":"fee_quoter","name":"initialize","parameters":[{"name":"max_fee_juels_per_msg","type":"u256"},{"name":"link_token","type":"address"},{"name":"token_price_staleness_threshold","type":"u64"},{"name":"fee_tokens","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"fee_quoter","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip","module":"fee_quoter","name":"token_transfer_fee_config_values","parameters":[{"name":"config","type":"TokenTransferFeeConfig"}]},{"package":"ccip","module":"fee_quoter","name":"update_prices","parameters":[{"name":"source_tokens","type":"vector\u003caddress\u003e"},{"name":"source_usd_per_token","type":"vector\u003cu256\u003e"},{"name":"gas_dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"gas_usd_per_unit_gas","type":"vector\u003cu256\u003e"}]},{"package":"ccip","module":"fee_quoter","name":"validate_32byte_address","parameters":[{"name":"encoded_address","type":"vector\u003cu8\u003e"},{"name":"min_value","type":"u256"}]},{"package":"ccip","module":"fee_quoter","name":"validate_dest_family_address","parameters":[{"name":"chain_family_selector","type":"vector\u003cu8\u003e"},{"name":"encoded_address","type":"vector\u003cu8\u003e"},{"name":"gas_limit","type":"u256"}]},{"package":"ccip","module":"fee_quoter","name":"validate_evm_address","parameters":[{"name":"encoded_address","type":"vector\u003cu8\u003e"}]}]`

func NewFeeQuoter(address aptos.AccountAddress, client aptos.AptosRpcClient) FeeQuoterInterface {
	contract := bind.NewBoundContract(address, "ccip", "fee_quoter", client)
	return FeeQuoterContract{
		BoundContract:    contract,
		feeQuoterEncoder: feeQuoterEncoder{BoundContract: contract},
	}
}

// Constants
const (
	ALLOW_OUT_OF_ORDER_EXECUTION                    bool   = true
	GAS_PRICE_BITS                                  byte   = 112
	MESSAGE_FIXED_BYTES                             uint64 = 32 * 15
	MESSAGE_FIXED_BYTES_PER_TOKEN                   uint64 = 32 * (4 + (3 + 2))
	CCIP_LOCK_OR_BURN_V1_RET_BYTES                  uint32 = 32
	SVM_EXTRA_ARGS_MAX_ACCOUNTS                     uint64 = 64
	SVM_MESSAGING_ACCOUNTS_OVERHEAD                 uint64 = 2
	SVM_ACCOUNT_BYTE_SIZE                           uint64 = 32
	SVM_TOKEN_TRANSFER_DATA_OVERHEAD                uint64 = (4 + 32) + 32 + 4 + 4 + 32 + 32 + 32 + 32 + 32 + 32 + 32
	E_ALREADY_INITIALIZED                           uint64 = 1
	E_INVALID_LINK_TOKEN                            uint64 = 2
	E_UNKNOWN_DEST_CHAIN_SELECTOR                   uint64 = 3
	E_UNKNOWN_TOKEN                                 uint64 = 4
	E_DEST_CHAIN_NOT_ENABLED                        uint64 = 5
	E_TOKEN_UPDATE_MISMATCH                         uint64 = 6
	E_GAS_UPDATE_MISMATCH                           uint64 = 7
	E_TOKEN_TRANSFER_FEE_CONFIG_MISMATCH            uint64 = 8
	E_FEE_TOKEN_NOT_SUPPORTED                       uint64 = 9
	E_TOKEN_NOT_SUPPORTED                           uint64 = 10
	E_UNKNOWN_CHAIN_FAMILY_SELECTOR                 uint64 = 11
	E_STALE_GAS_PRICE                               uint64 = 12
	E_MESSAGE_TOO_LARGE                             uint64 = 13
	E_UNSUPPORTED_NUMBER_OF_TOKENS                  uint64 = 14
	E_INVALID_EVM_ADDRESS                           uint64 = 15
	E_INVALID_32BYTES_ADDRESS                       uint64 = 16
	E_FEE_TOKEN_COST_TOO_HIGH                       uint64 = 17
	E_MESSAGE_GAS_LIMIT_TOO_HIGH                    uint64 = 18
	E_EXTRA_ARG_OUT_OF_ORDER_EXECUTION_MUST_BE_TRUE uint64 = 19
	E_INVALID_EXTRA_ARGS_TAG                        uint64 = 20
	E_INVALID_EXTRA_ARGS_DATA                       uint64 = 21
	E_INVALID_TOKEN_RECEIVER                        uint64 = 22
	E_MESSAGE_COMPUTE_UNIT_LIMIT_TOO_HIGH           uint64 = 23
	E_MESSAGE_FEE_TOO_HIGH                          uint64 = 24
	E_SOURCE_TOKEN_DATA_TOO_LARGE                   uint64 = 25
	E_INVALID_DEST_CHAIN_SELECTOR                   uint64 = 26
	E_INVALID_GAS_LIMIT                             uint64 = 27
	E_INVALID_CHAIN_FAMILY_SELECTOR                 uint64 = 28
	E_TO_TOKEN_AMOUNT_TOO_LARGE                     uint64 = 29
	E_UNKNOWN_FUNCTION                              uint64 = 30
	E_ZERO_TOKEN_PRICE                              uint64 = 31
	E_TOO_MANY_SVM_EXTRA_ARGS_ACCOUNTS              uint64 = 32
	E_INVALID_SVM_EXTRA_ARGS_WRITABLE_BITMAP        uint64 = 33
	E_INVALID_FEE_RANGE                             uint64 = 34
	E_INVALID_DEST_BYTES_OVERHEAD                   uint64 = 35
	E_INVALID_SVM_RECEIVER_LENGTH                   uint64 = 36
	E_TOKEN_AMOUNT_MISMATCH                         uint64 = 37
	E_INVALID_SVM_ACCOUNT_LENGTH                    uint64 = 38
)

// Structs

type FeeQuoterState struct {
	MaxFeeJuelsPerMsg            *big.Int               `move:"u256"`
	LinkToken                    aptos.AccountAddress   `move:"address"`
	TokenPriceStalenessThreshold uint64                 `move:"u64"`
	FeeTokens                    []aptos.AccountAddress `move:"vector<address>"`
}

type StaticConfig struct {
	MaxFeeJuelsPerMsg            *big.Int             `move:"u256"`
	LinkToken                    aptos.AccountAddress `move:"address"`
	TokenPriceStalenessThreshold uint64               `move:"u64"`
}

type DestChainConfig struct {
	IsEnabled                         bool   `move:"bool"`
	MaxNumberOfTokensPerMsg           uint16 `move:"u16"`
	MaxDataBytes                      uint32 `move:"u32"`
	MaxPerMsgGasLimit                 uint32 `move:"u32"`
	DestGasOverhead                   uint32 `move:"u32"`
	DestGasPerPayloadByteBase         byte   `move:"u8"`
	DestGasPerPayloadByteHigh         byte   `move:"u8"`
	DestGasPerPayloadByteThreshold    uint16 `move:"u16"`
	DestDataAvailabilityOverheadGas   uint32 `move:"u32"`
	DestGasPerDataAvailabilityByte    uint16 `move:"u16"`
	DestDataAvailabilityMultiplierBps uint16 `move:"u16"`
	ChainFamilySelector               []byte `move:"vector<u8>"`
	EnforceOutOfOrder                 bool   `move:"bool"`
	DefaultTokenFeeUsdCents           uint16 `move:"u16"`
	DefaultTokenDestGasOverhead       uint32 `move:"u32"`
	DefaultTxGasLimit                 uint32 `move:"u32"`
	GasMultiplierWeiPerEth            uint64 `move:"u64"`
	GasPriceStalenessThreshold        uint32 `move:"u32"`
	NetworkFeeUsdCents                uint32 `move:"u32"`
}

type TokenTransferFeeConfig struct {
	MinFeeUsdCents    uint32 `move:"u32"`
	MaxFeeUsdCents    uint32 `move:"u32"`
	DeciBps           uint16 `move:"u16"`
	DestGasOverhead   uint32 `move:"u32"`
	DestBytesOverhead uint32 `move:"u32"`
	IsEnabled         bool   `move:"bool"`
}

type TimestampedPrice struct {
	Value     *big.Int `move:"u256"`
	Timestamp uint64   `move:"u64"`
}

type FeeTokenAdded struct {
	FeeToken aptos.AccountAddress `move:"address"`
}

type FeeTokenRemoved struct {
	FeeToken aptos.AccountAddress `move:"address"`
}

type TokenTransferFeeConfigAdded struct {
	DestChainSelector      uint64                 `move:"u64"`
	Token                  aptos.AccountAddress   `move:"address"`
	TokenTransferFeeConfig TokenTransferFeeConfig `move:"TokenTransferFeeConfig"`
}

type TokenTransferFeeConfigRemoved struct {
	DestChainSelector uint64               `move:"u64"`
	Token             aptos.AccountAddress `move:"address"`
}

type UsdPerTokenUpdated struct {
	Token       aptos.AccountAddress `move:"address"`
	UsdPerToken *big.Int             `move:"u256"`
	Timestamp   uint64               `move:"u64"`
}

type UsdPerUnitGasUpdated struct {
	DestChainSelector uint64   `move:"u64"`
	UsdPerUnitGas     *big.Int `move:"u256"`
	Timestamp         uint64   `move:"u64"`
}

type DestChainAdded struct {
	DestChainSelector uint64          `move:"u64"`
	DestChainConfig   DestChainConfig `move:"DestChainConfig"`
}

type DestChainConfigUpdated struct {
	DestChainSelector uint64          `move:"u64"`
	DestChainConfig   DestChainConfig `move:"DestChainConfig"`
}

type PremiumMultiplierWeiPerEthUpdated struct {
	Token                      aptos.AccountAddress `move:"address"`
	PremiumMultiplierWeiPerEth uint64               `move:"u64"`
}

type McmsCallback struct {
}

type FeeQuoterContract struct {
	*bind.BoundContract
	feeQuoterEncoder
}

var _ FeeQuoterInterface = FeeQuoterContract{}

func (c FeeQuoterContract) Encoder() FeeQuoterEncoder {
	return c.feeQuoterEncoder
}

// View Functions

func (c FeeQuoterContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.TypeAndVersion()
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

func (c FeeQuoterContract) GetTokenPrice(opts *bind.CallOpts, token aptos.AccountAddress) (TimestampedPrice, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetTokenPrice(token)
	if err != nil {
		return *new(TimestampedPrice), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(TimestampedPrice), err
	}

	var (
		r0 TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(TimestampedPrice), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetTokenPrices(opts *bind.CallOpts, tokens []aptos.AccountAddress) ([]TimestampedPrice, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetTokenPrices(tokens)
	if err != nil {
		return *new([]TimestampedPrice), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]TimestampedPrice), err
	}

	var (
		r0 []TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]TimestampedPrice), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetDestChainGasPrice(opts *bind.CallOpts, destChainSelector uint64) (TimestampedPrice, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetDestChainGasPrice(destChainSelector)
	if err != nil {
		return *new(TimestampedPrice), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(TimestampedPrice), err
	}

	var (
		r0 TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(TimestampedPrice), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetTokenAndGasPrices(opts *bind.CallOpts, token aptos.AccountAddress, destChainSelector uint64) (*big.Int, *big.Int, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetTokenAndGasPrices(token, destChainSelector)
	if err != nil {
		return *new(*big.Int), *new(*big.Int), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*big.Int), *new(*big.Int), err
	}

	var (
		r0 *big.Int
		r1 *big.Int
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1); err != nil {
		return *new(*big.Int), *new(*big.Int), err
	}
	return r0, r1, nil
}

func (c FeeQuoterContract) ConvertTokenAmount(opts *bind.CallOpts, fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ConvertTokenAmount(fromToken, fromTokenAmount, toToken)
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

func (c FeeQuoterContract) GetFeeTokens(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetFeeTokens()
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	var (
		r0 []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]aptos.AccountAddress), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetTokenTransferFeeConfig(opts *bind.CallOpts, destChainSelector uint64, token aptos.AccountAddress) (TokenTransferFeeConfig, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetTokenTransferFeeConfig(destChainSelector, token)
	if err != nil {
		return *new(TokenTransferFeeConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(TokenTransferFeeConfig), err
	}

	var (
		r0 TokenTransferFeeConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(TokenTransferFeeConfig), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetValidatedFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, localTokenAddresses []aptos.AccountAddress, localTokenAmounts []uint64, TokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, FeeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetValidatedFee(destChainSelector, receiver, data, localTokenAddresses, localTokenAmounts, TokenStoreAddresses, feeToken, FeeTokenStore, extraArgs)
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

func (c FeeQuoterContract) GetPremiumMultiplierWeiPerEth(opts *bind.CallOpts, token aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetPremiumMultiplierWeiPerEth(token)
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

func (c FeeQuoterContract) GetTokenReceiver(opts *bind.CallOpts, destChainSelector uint64, extraArgs []byte, messageReceiver []byte) ([]byte, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetTokenReceiver(destChainSelector, extraArgs, messageReceiver)
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

func (c FeeQuoterContract) ProcessMessageArgs(opts *bind.CallOpts, destChainSelector uint64, feeToken aptos.AccountAddress, feeTokenAmount uint64, extraArgs []byte, localTokenAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, destPoolDatas [][]byte) (*big.Int, bool, []byte, [][]byte, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ProcessMessageArgs(destChainSelector, feeToken, feeTokenAmount, extraArgs, localTokenAddresses, destTokenAddresses, destPoolDatas)
	if err != nil {
		return *new(*big.Int), *new(bool), *new([]byte), *new([][]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*big.Int), *new(bool), *new([]byte), *new([][]byte), err
	}

	var (
		r0 *big.Int
		r1 bool
		r2 []byte
		r3 [][]byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2, &r3); err != nil {
		return *new(*big.Int), *new(bool), *new([]byte), *new([][]byte), err
	}
	return r0, r1, r2, r3, nil
}

func (c FeeQuoterContract) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (DestChainConfig, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetDestChainConfig(destChainSelector)
	if err != nil {
		return *new(DestChainConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(DestChainConfig), err
	}

	var (
		r0 DestChainConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(DestChainConfig), err
	}
	return r0, nil
}

func (c FeeQuoterContract) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.GetStaticConfig()
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

// Entry Functions

func (c FeeQuoterContract) Initialize(opts *bind.TransactOpts, maxFeeJuelsPerMsg *big.Int, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.Initialize(maxFeeJuelsPerMsg, linkToken, tokenPriceStalenessThreshold, feeTokens)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c FeeQuoterContract) ApplyFeeTokenUpdates(opts *bind.TransactOpts, feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ApplyFeeTokenUpdates(feeTokensToRemove, feeTokensToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c FeeQuoterContract) ApplyTokenTransferFeeConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ApplyTokenTransferFeeConfigUpdates(destChainSelector, addTokens, addMinFeeUsdCents, addMaxFeeUsdCents, addDeciBps, addDestGasOverhead, addDestBytesOverhead, addIsEnabled, removeTokens)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c FeeQuoterContract) ApplyPremiumMultiplierWeiPerEthUpdates(opts *bind.TransactOpts, tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ApplyPremiumMultiplierWeiPerEthUpdates(tokens, premiumMultiplierWeiPerEth)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c FeeQuoterContract) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, isEnabled bool, maxNumberOfTokensPerMsg uint16, maxDataBytes uint32, maxPerMsgGasLimit uint32, destGasOverhead uint32, destGasPerPayloadByteBase byte, destGasPerPayloadByteHigh byte, destGasPerPayloadByteThreshold uint16, destDataAvailabilityOverheadGas uint32, destGasPerDataAvailabilityByte uint16, destDataAvailabilityMultiplierBps uint16, chainFamilySelector []byte, enforceOutOfOrder bool, defaultTokenFeeUsdCents uint16, defaultTokenDestGasOverhead uint32, defaultTxGasLimit uint32, gasMultiplierWeiPerEth uint64, gasPriceStalenessThreshold uint32, networkFeeUsdCents uint32) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.feeQuoterEncoder.ApplyDestChainConfigUpdates(destChainSelector, isEnabled, maxNumberOfTokensPerMsg, maxDataBytes, maxPerMsgGasLimit, destGasOverhead, destGasPerPayloadByteBase, destGasPerPayloadByteHigh, destGasPerPayloadByteThreshold, destDataAvailabilityOverheadGas, destGasPerDataAvailabilityByte, destDataAvailabilityMultiplierBps, chainFamilySelector, enforceOutOfOrder, defaultTokenFeeUsdCents, defaultTokenDestGasOverhead, defaultTxGasLimit, gasMultiplierWeiPerEth, gasPriceStalenessThreshold, networkFeeUsdCents)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type feeQuoterEncoder struct {
	*bind.BoundContract
}

func (c feeQuoterEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c feeQuoterEncoder) GetTokenPrice(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_price", nil, []string{
		"address",
	}, []any{
		token,
	})
}

func (c feeQuoterEncoder) GetTokenPrices(tokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_prices", nil, []string{
		"vector<address>",
	}, []any{
		tokens,
	})
}

func (c feeQuoterEncoder) GetDestChainGasPrice(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chain_gas_price", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c feeQuoterEncoder) GetTokenAndGasPrices(token aptos.AccountAddress, destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_and_gas_prices", nil, []string{
		"address",
		"u64",
	}, []any{
		token,
		destChainSelector,
	})
}

func (c feeQuoterEncoder) ConvertTokenAmount(fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("convert_token_amount", nil, []string{
		"address",
		"u64",
		"address",
	}, []any{
		fromToken,
		fromTokenAmount,
		toToken,
	})
}

func (c feeQuoterEncoder) GetFeeTokens() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_fee_tokens", nil, []string{}, []any{})
}

func (c feeQuoterEncoder) GetTokenTransferFeeConfig(destChainSelector uint64, token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_transfer_fee_config", nil, []string{
		"u64",
		"address",
	}, []any{
		destChainSelector,
		token,
	})
}

func (c feeQuoterEncoder) GetValidatedFee(destChainSelector uint64, receiver []byte, data []byte, localTokenAddresses []aptos.AccountAddress, localTokenAmounts []uint64, TokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, FeeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_validated_fee", nil, []string{
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
		localTokenAddresses,
		localTokenAmounts,
		TokenStoreAddresses,
		feeToken,
		FeeTokenStore,
		extraArgs,
	})
}

func (c feeQuoterEncoder) GetPremiumMultiplierWeiPerEth(token aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_premium_multiplier_wei_per_eth", nil, []string{
		"address",
	}, []any{
		token,
	})
}

func (c feeQuoterEncoder) GetTokenReceiver(destChainSelector uint64, extraArgs []byte, messageReceiver []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_receiver", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		destChainSelector,
		extraArgs,
		messageReceiver,
	})
}

func (c feeQuoterEncoder) ProcessMessageArgs(destChainSelector uint64, feeToken aptos.AccountAddress, feeTokenAmount uint64, extraArgs []byte, localTokenAddresses []aptos.AccountAddress, destTokenAddresses [][]byte, destPoolDatas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("process_message_args", nil, []string{
		"u64",
		"address",
		"u64",
		"vector<u8>",
		"vector<address>",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		destChainSelector,
		feeToken,
		feeTokenAmount,
		extraArgs,
		localTokenAddresses,
		destTokenAddresses,
		destPoolDatas,
	})
}

func (c feeQuoterEncoder) GetDestChainConfig(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chain_config", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c feeQuoterEncoder) GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_static_config", nil, []string{}, []any{})
}

func (c feeQuoterEncoder) Initialize(maxFeeJuelsPerMsg *big.Int, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u256",
		"address",
		"u64",
		"vector<address>",
	}, []any{
		maxFeeJuelsPerMsg,
		linkToken,
		tokenPriceStalenessThreshold,
		feeTokens,
	})
}

func (c feeQuoterEncoder) ApplyFeeTokenUpdates(feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_fee_token_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		feeTokensToRemove,
		feeTokensToAdd,
	})
}

func (c feeQuoterEncoder) ApplyTokenTransferFeeConfigUpdates(destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_token_transfer_fee_config_updates", nil, []string{
		"u64",
		"vector<address>",
		"vector<u32>",
		"vector<u32>",
		"vector<u16>",
		"vector<u32>",
		"vector<u32>",
		"vector<bool>",
		"vector<address>",
	}, []any{
		destChainSelector,
		addTokens,
		addMinFeeUsdCents,
		addMaxFeeUsdCents,
		addDeciBps,
		addDestGasOverhead,
		addDestBytesOverhead,
		addIsEnabled,
		removeTokens,
	})
}

func (c feeQuoterEncoder) ApplyPremiumMultiplierWeiPerEthUpdates(tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_premium_multiplier_wei_per_eth_updates", nil, []string{
		"vector<address>",
		"vector<u64>",
	}, []any{
		tokens,
		premiumMultiplierWeiPerEth,
	})
}

func (c feeQuoterEncoder) ApplyDestChainConfigUpdates(destChainSelector uint64, isEnabled bool, maxNumberOfTokensPerMsg uint16, maxDataBytes uint32, maxPerMsgGasLimit uint32, destGasOverhead uint32, destGasPerPayloadByteBase byte, destGasPerPayloadByteHigh byte, destGasPerPayloadByteThreshold uint16, destDataAvailabilityOverheadGas uint32, destGasPerDataAvailabilityByte uint16, destDataAvailabilityMultiplierBps uint16, chainFamilySelector []byte, enforceOutOfOrder bool, defaultTokenFeeUsdCents uint16, defaultTokenDestGasOverhead uint32, defaultTxGasLimit uint32, gasMultiplierWeiPerEth uint64, gasPriceStalenessThreshold uint32, networkFeeUsdCents uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_dest_chain_config_updates", nil, []string{
		"u64",
		"bool",
		"u16",
		"u32",
		"u32",
		"u32",
		"u8",
		"u8",
		"u16",
		"u32",
		"u16",
		"u16",
		"vector<u8>",
		"bool",
		"u16",
		"u32",
		"u32",
		"u64",
		"u32",
		"u32",
	}, []any{
		destChainSelector,
		isEnabled,
		maxNumberOfTokensPerMsg,
		maxDataBytes,
		maxPerMsgGasLimit,
		destGasOverhead,
		destGasPerPayloadByteBase,
		destGasPerPayloadByteHigh,
		destGasPerPayloadByteThreshold,
		destDataAvailabilityOverheadGas,
		destGasPerDataAvailabilityByte,
		destDataAvailabilityMultiplierBps,
		chainFamilySelector,
		enforceOutOfOrder,
		defaultTokenFeeUsdCents,
		defaultTokenDestGasOverhead,
		defaultTxGasLimit,
		gasMultiplierWeiPerEth,
		gasPriceStalenessThreshold,
		networkFeeUsdCents,
	})
}

func (c feeQuoterEncoder) UpdatePrices(sourceTokens []aptos.AccountAddress, sourceUsdPerToken []*big.Int, gasDestChainSelectors []uint64, gasUsdPerUnitGas []*big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("update_prices", nil, []string{
		"vector<address>",
		"vector<u256>",
		"vector<u64>",
		"vector<u256>",
	}, []any{
		sourceTokens,
		sourceUsdPerToken,
		gasDestChainSelectors,
		gasUsdPerUnitGas,
	})
}

func (c feeQuoterEncoder) DecodeGenericExtraArgsV2(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("decode_generic_extra_args_v2", nil, []string{
		"vector<u8>",
	}, []any{
		extraArgs,
	})
}

func (c feeQuoterEncoder) DecodeSvmExtraArgs(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("decode_svm_extra_args", nil, []string{
		"vector<u8>",
	}, []any{
		extraArgs,
	})
}

func (c feeQuoterEncoder) DecodeSvmExtraArgsV1(extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("decode_svm_extra_args_v1", nil, []string{
		"vector<u8>",
	}, []any{
		extraArgs,
	})
}

func (c feeQuoterEncoder) CalcUsdValueFromTokenAmount(tokenAmount uint64, tokenPrice *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calc_usd_value_from_token_amount", nil, []string{
		"u64",
		"u256",
	}, []any{
		tokenAmount,
		tokenPrice,
	})
}

func (c feeQuoterEncoder) ValidateDestFamilyAddress(chainFamilySelector []byte, encodedAddress []byte, gasLimit *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("validate_dest_family_address", nil, []string{
		"vector<u8>",
		"vector<u8>",
		"u256",
	}, []any{
		chainFamilySelector,
		encodedAddress,
		gasLimit,
	})
}

func (c feeQuoterEncoder) ValidateEvmAddress(encodedAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("validate_evm_address", nil, []string{
		"vector<u8>",
	}, []any{
		encodedAddress,
	})
}

func (c feeQuoterEncoder) Validate32byteAddress(encodedAddress []byte, minValue *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("validate_32byte_address", nil, []string{
		"vector<u8>",
		"u256",
	}, []any{
		encodedAddress,
		minValue,
	})
}

func (c feeQuoterEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c feeQuoterEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}

func (c feeQuoterEncoder) DestChainConfigValues(config DestChainConfig) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("dest_chain_config_values", nil, []string{
		"DestChainConfig",
	}, []any{
		config,
	})
}

func (c feeQuoterEncoder) TokenTransferFeeConfigValues(config TokenTransferFeeConfig) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_transfer_fee_config_values", nil, []string{
		"TokenTransferFeeConfig",
	}, []any{
		config,
	})
}
