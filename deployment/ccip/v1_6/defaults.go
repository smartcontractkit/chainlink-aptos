package v1_6

import (
	"encoding/hex"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_3/fee_quoter"
)

const (
	EVMFamilySelector   = "2812d52c"
	SVMFamilySelector   = "1e10bdc4"
	AptosFamilySelector = "ac77ffec"
	TVMFamilySelector   = "647e2ba9"
	SuiFamilySelector   = "c4e05953"
)

const (
	evmDestGasOverhead             = 300_000
	evmCalldataGasPerByteBase      = 16
	evmCalldataGasPerByteHigh      = 40
	evmCalldataGasPerByteThreshold = 3000
)

func DefaultFeeQuoterDestChainConfig(configEnabled bool, destChainSelector ...uint64) fee_quoter.FeeQuoterDestChainConfig {
	familySelector, _ := hex.DecodeString(EVMFamilySelector)
	networkFeeUSDCents := uint32(10)
	defaultTokenFeeUSDCents := uint16(25)
	if len(destChainSelector) > 0 {
		destFamily, _ := chain_selectors.GetSelectorFamily(destChainSelector[0])
		switch destFamily {
		case chain_selectors.FamilySolana:
			familySelector, _ = hex.DecodeString(SVMFamilySelector)
			defaultTokenFeeUSDCents = 35
		case chain_selectors.FamilyAptos:
			familySelector, _ = hex.DecodeString(AptosFamilySelector)
		case chain_selectors.FamilyTon:
			familySelector, _ = hex.DecodeString(TVMFamilySelector)
		case chain_selectors.FamilySui:
			familySelector, _ = hex.DecodeString(SuiFamilySelector)
		case chain_selectors.FamilyEVM:
			if isEthereumChain(destChainSelector[0]) {
				networkFeeUSDCents = 50
				defaultTokenFeeUSDCents = 150
			}
		}
	}
	return fee_quoter.FeeQuoterDestChainConfig{
		IsEnabled:                         configEnabled,
		MaxNumberOfTokensPerMsg:           10,
		MaxDataBytes:                      30_000,
		MaxPerMsgGasLimit:                 3_000_000,
		DestGasOverhead:                   evmDestGasOverhead,
		DefaultTokenFeeUSDCents:           defaultTokenFeeUSDCents,
		DestGasPerPayloadByteBase:         evmCalldataGasPerByteBase,
		DestGasPerPayloadByteHigh:         evmCalldataGasPerByteHigh,
		DestGasPerPayloadByteThreshold:    evmCalldataGasPerByteThreshold,
		DestDataAvailabilityOverheadGas:   100,
		DestGasPerDataAvailabilityByte:    16,
		DestDataAvailabilityMultiplierBps: 1,
		DefaultTokenDestGasOverhead:       90_000,
		DefaultTxGasLimit:                 200_000,
		GasMultiplierWeiPerEth:            11e17,
		NetworkFeeUSDCents:                networkFeeUSDCents,
		ChainFamilySelector:               [4]byte(familySelector),
		GasPriceStalenessThreshold:        90000,
	}
}

func isEthereumChain(selector uint64) bool {
	return selector == chain_selectors.ETHEREUM_MAINNET.Selector ||
		selector == chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector ||
		selector == chain_selectors.ETHEREUM_TESTNET_HOODI.Selector
}
