package module_fee_quoter

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

type FeeQuoterInterface interface {
	GetTokenPrice(opts *bind.CallOpts, token aptos.AccountAddress) (TimestampedPrice, error)
	GetTokenPrices(opts *bind.CallOpts, tokens []aptos.AccountAddress) ([]TimestampedPrice, error)
	GetDestChainGasPrice(opts *bind.CallOpts, destChainSelector uint64) (TimestampedPrice, error)
	GetTokenAndGasPrices(opts *bind.CallOpts, token aptos.AccountAddress, destChainSelector uint64) (*big.Int, *big.Int, error)
	ConvertTokenAmount(opts *bind.CallOpts, fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (uint64, error)
	GetFeeTokens(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetTokenTransferFeeConfig(opts *bind.CallOpts, destChainSelector uint64, token aptos.AccountAddress) (TokenTransferFeeConfig, error)
	GetPremiumMultiplierWeiPerEth(opts *bind.CallOpts, token aptos.AccountAddress) (uint64, error)
	GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (DestChainConfig, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)

	Initialize(opts *bind.TransactOpts, maxFeeJuelsPerMsg uint64, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyFeeTokenUpdates(opts *bind.TransactOpts, feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyTokenTransferFeeConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyPremiumMultiplierWeiPerEthUpdates(opts *bind.TransactOpts, tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, config DestChainConfig) (*api.PendingTransaction, error)
}

// Structs

type StaticConfig struct {
	MaxFeeJuelsPerMsg            uint64
	LinkToken                    aptos.AccountAddress
	TokenPriceStalenessThreshold uint64
}

type DestChainConfig struct {
	IsEnabled                         bool
	MaxNumberOfTokensPerMsg           uint16
	MaxDataBytes                      uint32
	MaxPerMsgGasLimit                 uint32
	DestGasOverhead                   uint32
	DestGasPerPayloadByteBase         uint8
	DestGasPerPayloadByteHigh         uint8
	DestGasPerPayloadByteThreshold    uint16
	DestDataAvailabilityOverheadGas   uint32
	DestGasPerDataAvailabilityByte    uint16
	DestDataAvailabilityMultiplierBps uint16
	ChainFamilySelector               []byte
	EnforceOutOfOrder                 bool
	DefaultTokenFeeUsdCents           uint16
	DefaultTokenDestGasOverhead       uint32
	DefaultTxGasLimit                 uint32
	GasMultiplierWeiPerEth            uint64
	GasPriceStalenessThreshold        uint32
	NetworkFeeUsdCents                uint32
}

type TokenTransferFeeConfig struct {
	MinFeeUsdCents    uint32
	MaxFeeUsdCents    uint32
	DeciBps           uint16
	DestGasOverhead   uint32
	FestBytesOverhead uint32
	IsEnabled         bool
}

type TimestampedPrice struct {
	Price         *big.Int
	TimestampSecs uint64
}

var _ FeeQuoterInterface = FeeQuoter{}

type FeeQuoter struct {
	FeeQuoterCaller
	FeeQuoterTransactor
}

type FeeQuoterCaller struct {
	*bind.BoundContract
}

func (f FeeQuoterCaller) EncodeGetTokenPrice(token aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_token_price", nil, []string{"address"}, []any{token})
}

func (f FeeQuoterCaller) GetTokenPrice(opts *bind.CallOpts, token aptos.AccountAddress) (TimestampedPrice, error) {
	module, function, typeTags, args, err := f.EncodeGetTokenPrice(token)
	if err != nil {
		return TimestampedPrice{}, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return TimestampedPrice{}, err
	}

	var (
		timestampedPrice TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(data, &timestampedPrice); err != nil {
		return TimestampedPrice{}, err
	}
	return timestampedPrice, nil
}

func (f FeeQuoterCaller) EncodeGetTokenPrices(tokens []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_token_prices", nil, []string{"vector<address>"}, []any{tokens})
}

func (f FeeQuoterCaller) GetTokenPrices(opts *bind.CallOpts, tokens []aptos.AccountAddress) ([]TimestampedPrice, error) {
	module, function, typeTags, args, err := f.EncodeGetTokenPrices(tokens)
	if err != nil {
		return nil, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return nil, err
	}

	var (
		timestampedPrices []TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(data, &timestampedPrices); err != nil {
		return nil, err
	}
	return timestampedPrices, nil
}

func (f FeeQuoterCaller) EncodeGetDestChainGasPrice(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_dest_chain_gas_price", nil, []string{"u64"}, []any{destChainSelector})
}

func (f FeeQuoterCaller) GetDestChainGasPrice(opts *bind.CallOpts, destChainSelector uint64) (TimestampedPrice, error) {
	module, function, typeTags, args, err := f.EncodeGetDestChainGasPrice(destChainSelector)
	if err != nil {
		return TimestampedPrice{}, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return TimestampedPrice{}, err
	}

	var (
		timestampedPrice TimestampedPrice
	)

	if err := codec.DecodeAptosJsonArray(data, &timestampedPrice); err != nil {
		return TimestampedPrice{}, err
	}
	return timestampedPrice, nil
}

func (f FeeQuoterCaller) EncodeGetTokenAndGasPrices(token aptos.AccountAddress, destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_token_and_gas_prices", nil, []string{"address", "u64"}, []any{token, destChainSelector})
}

func (f FeeQuoterCaller) GetTokenAndGasPrices(opts *bind.CallOpts, token aptos.AccountAddress, destChainSelector uint64) (*big.Int, *big.Int, error) {
	module, function, typeTags, args, err := f.EncodeGetTokenAndGasPrices(token, destChainSelector)
	if err != nil {
		return nil, nil, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return nil, nil, err
	}

	var (
		tokenPrice *big.Int
		gasPrice   *big.Int
	)

	if err := codec.DecodeAptosJsonArray(data, &tokenPrice, &gasPrice); err != nil {
		return nil, nil, err
	}
	return tokenPrice, gasPrice, nil
}

func (f FeeQuoterCaller) EncodeConvertTokenAmount(fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("convert_token_amount", nil, []string{"address", "u64", "address"}, []any{fromToken, fromTokenAmount, toToken})
}

func (f FeeQuoterCaller) ConvertTokenAmount(opts *bind.CallOpts, fromToken aptos.AccountAddress, fromTokenAmount uint64, toToken aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := f.EncodeConvertTokenAmount(fromToken, fromTokenAmount, toToken)
	if err != nil {
		return 0, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var (
		toTokenAmount uint64
	)

	if err := codec.DecodeAptosJsonArray(data, &toTokenAmount); err != nil {
		return 0, err
	}
	return toTokenAmount, nil
}

func (f FeeQuoterCaller) EncodeGetFeeTokens() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_fee_tokens", nil, nil, nil)
}

func (f FeeQuoterCaller) GetFeeTokens(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := f.EncodeGetFeeTokens()
	if err != nil {
		return nil, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return nil, err
	}

	var (
		feeTokens []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(data, &feeTokens); err != nil {
		return nil, err
	}
	return feeTokens, nil
}

func (f FeeQuoterCaller) EncodeGetTokenTransferFeeConfig(destChainSelector uint64, token aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_token_transfer_fee_config", nil, []string{"u64", "address"}, []any{destChainSelector, token})
}

func (f FeeQuoterCaller) GetTokenTransferFeeConfig(opts *bind.CallOpts, destChainSelector uint64, token aptos.AccountAddress) (TokenTransferFeeConfig, error) {
	module, function, typeTags, args, err := f.EncodeGetTokenTransferFeeConfig(destChainSelector, token)
	if err != nil {
		return TokenTransferFeeConfig{}, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return TokenTransferFeeConfig{}, err
	}

	var (
		tokenTransferFeeConfig TokenTransferFeeConfig
	)

	if err := codec.DecodeAptosJsonArray(data, &tokenTransferFeeConfig); err != nil {
		return TokenTransferFeeConfig{}, err
	}
	return tokenTransferFeeConfig, nil
}

func (f FeeQuoterCaller) EncodeGetPremiumMultiplierWeiPerEth(token aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_premium_multiplier_wei_per_eth", nil, []string{"address"}, []any{token})
}

func (f FeeQuoterCaller) GetPremiumMultiplierWeiPerEth(opts *bind.CallOpts, token aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := f.EncodeGetPremiumMultiplierWeiPerEth(token)
	if err != nil {
		return 0, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var (
		premiumMultiplierWeiPerEth uint64
	)

	if err := codec.DecodeAptosJsonArray(data, &premiumMultiplierWeiPerEth); err != nil {
		return 0, err
	}
	return premiumMultiplierWeiPerEth, nil
}

func (f FeeQuoterCaller) EncodeGetDestChainConfig(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_dest_chain_config", nil, []string{"u64"}, []any{destChainSelector})
}

func (f FeeQuoterCaller) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (DestChainConfig, error) {
	module, function, typeTags, args, err := f.EncodeGetDestChainConfig(destChainSelector)
	if err != nil {
		return DestChainConfig{}, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return DestChainConfig{}, err
	}

	var (
		destChainConfig DestChainConfig
	)

	if err := codec.DecodeAptosJsonArray(data, &destChainConfig); err != nil {
		return DestChainConfig{}, err
	}
	return destChainConfig, nil
}

func (f FeeQuoterCaller) EncodeGetStaticConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("get_static_config", nil, nil, nil)
}

func (f FeeQuoterCaller) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := f.EncodeGetStaticConfig()
	if err != nil {
		return StaticConfig{}, err
	}

	data, err := f.Call(opts, module, function, typeTags, args)
	if err != nil {
		return StaticConfig{}, err
	}

	var (
		staticConfig StaticConfig
	)

	if err := codec.DecodeAptosJsonArray(data, &staticConfig); err != nil {
		return StaticConfig{}, err
	}
	return staticConfig, nil
}

type FeeQuoterTransactor struct {
	*bind.BoundContract
}

func (f FeeQuoterTransactor) EncodeInitialize(maxFeeJuelsPerMsg uint64, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("initialize", nil, []string{"u64", "address", "u64", "vector<address>"}, []any{maxFeeJuelsPerMsg, linkToken, tokenPriceStalenessThreshold, feeTokens})
}

func (f FeeQuoterTransactor) Initialize(opts *bind.TransactOpts, maxFeeJuelsPerMsg uint64, linkToken aptos.AccountAddress, tokenPriceStalenessThreshold uint64, feeTokens []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := f.EncodeInitialize(maxFeeJuelsPerMsg, linkToken, tokenPriceStalenessThreshold, feeTokens)
	if err != nil {
		return nil, err
	}
	return f.Transact(opts, module, function, typeTags, args)
}

func (f FeeQuoterTransactor) EncodeApplyFeeTokenUpdates(feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("apply_fee_token_updates", nil, []string{"vector<address>", "vector<address>"}, []any{feeTokensToRemove, feeTokensToAdd})
}

func (f FeeQuoterTransactor) ApplyFeeTokenUpdates(opts *bind.TransactOpts, feeTokensToRemove []aptos.AccountAddress, feeTokensToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := f.EncodeApplyFeeTokenUpdates(feeTokensToRemove, feeTokensToAdd)
	if err != nil {
		return nil, err
	}
	return f.Transact(opts, module, function, typeTags, args)
}

func (f FeeQuoterTransactor) EncodeApplyTokenTransferFeeConfigUpdates(destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode(
		"apply_token_transfer_fee_config_updates",
		nil,
		[]string{
			"u64",
			"vector<address>",
			"vector<u32>",
			"vector<u32>",
			"vector<u16>",
			"vector<u32>",
			"vector<u32>",
			"vector<bool>",
			"vector<address>",
		},
		[]any{
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

func (f FeeQuoterTransactor) ApplyTokenTransferFeeConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, addTokens []aptos.AccountAddress, addMinFeeUsdCents []uint32, addMaxFeeUsdCents []uint32, addDeciBps []uint16, addDestGasOverhead []uint32, addDestBytesOverhead []uint32, addIsEnabled []bool, removeTokens []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := f.EncodeApplyTokenTransferFeeConfigUpdates(
		destChainSelector,
		addTokens,
		addMinFeeUsdCents,
		addMaxFeeUsdCents,
		addDeciBps,
		addDestGasOverhead,
		addDestBytesOverhead,
		addIsEnabled,
		removeTokens,
	)
	if err != nil {
		return nil, err
	}
	return f.Transact(opts, module, function, typeTags, args)
}

func (f FeeQuoterTransactor) EncodeApplyPremiumMultiplierWeiPerEthUpdates(tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode("apply_premium_multiplier_wei_per_eth_updates", nil, []string{"vector<address>", "vector<u64>"}, []any{tokens, premiumMultiplierWeiPerEth})
}

func (f FeeQuoterTransactor) ApplyPremiumMultiplierWeiPerEthUpdates(opts *bind.TransactOpts, tokens []aptos.AccountAddress, premiumMultiplierWeiPerEth []uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := f.EncodeApplyPremiumMultiplierWeiPerEthUpdates(tokens, premiumMultiplierWeiPerEth)
	if err != nil {
		return nil, err
	}
	return f.Transact(opts, module, function, typeTags, args)
}
func (f FeeQuoterTransactor) EncodeApplyDestChainConfigUpdates(destChainSelector uint64, config DestChainConfig) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return f.Encode(
		"apply_dest_chain_config_updates",
		nil,
		[]string{
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
		},
		[]any{
			destChainSelector,
			config.IsEnabled,
			config.MaxNumberOfTokensPerMsg,
			config.MaxDataBytes,
			config.MaxPerMsgGasLimit,
			config.DestGasOverhead,
			config.DestGasPerPayloadByteBase,
			config.DestGasPerPayloadByteHigh,
			config.DestGasPerPayloadByteThreshold,
			config.DestDataAvailabilityOverheadGas,
			config.DestGasPerDataAvailabilityByte,
			config.DestDataAvailabilityMultiplierBps,
			config.ChainFamilySelector,
			config.EnforceOutOfOrder,
			config.DefaultTokenFeeUsdCents,
			config.DefaultTokenDestGasOverhead,
			config.DefaultTxGasLimit,
			config.GasMultiplierWeiPerEth,
			config.GasPriceStalenessThreshold,
			config.NetworkFeeUsdCents,
		},
	)
}

func (f FeeQuoterTransactor) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelector uint64, config DestChainConfig) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := f.EncodeApplyDestChainConfigUpdates(destChainSelector, config)
	if err != nil {
		return nil, err
	}
	return f.Transact(opts, module, function, typeTags, args)
}
