package v1_6

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"

	aptos_fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
)

const (
	aptosLaneMaxDataBytes                      = 40_000
	aptosLaneMaxPerMsgGasLimit                 = 4_000_000
	aptosLaneDestGasOverhead                   = 300_000
	aptosLaneDestGasPerPayloadByteBase         = 16
	aptosLaneDestGasPerPayloadByteHigh         = 40
	aptosLaneDestGasPerPayloadByteThreshold    = 3000
	aptosLaneDestDataAvailabilityOverheadGas   = 700
	aptosLaneDestGasPerDataAvailabilityByte    = 17
	aptosLaneDestDataAvailabilityMultiplierBps = 2
	aptosLaneDefaultTokenFeeUSDCents           = 30
	aptosLaneDefaultTokenDestGasOverhead       = 100_000
	aptosLaneDefaultTxGasLimit                 = 100_000
	aptosLaneNetworkFeeUSDCents                = 20
	aptosLaneMaxNumberOfTokensPerMsg           = 11
	aptosLaneGasMultiplierWeiPerEth            = 1e7
	aptosLaneGasPriceStalenessThreshold        = 2
	aptosLaneDefaultGasPrice                   = 1e17
)

// DefaultAptosLaneFeeQuoterDestChainConfig returns default FeeQuoter destination
// chain config when Aptos is the remote (destination) chain in a lane.
func DefaultAptosLaneFeeQuoterDestChainConfig() lanes.FeeQuoterDestChainConfig {
	familySelector, _ := hex.DecodeString(AptosFamilySelector)
	return lanes.FeeQuoterDestChainConfig{
		IsEnabled:                   true,
		MaxDataBytes:                aptosLaneMaxDataBytes,
		MaxPerMsgGasLimit:           aptosLaneMaxPerMsgGasLimit,
		DestGasOverhead:             aptosLaneDestGasOverhead,
		DestGasPerPayloadByteBase:   aptosLaneDestGasPerPayloadByteBase,
		ChainFamilySelector:         binary.BigEndian.Uint32(familySelector),
		DefaultTokenFeeUSDCents:     aptosLaneDefaultTokenFeeUSDCents,
		DefaultTokenDestGasOverhead: aptosLaneDefaultTokenDestGasOverhead,
		DefaultTxGasLimit:           aptosLaneDefaultTxGasLimit,
		NetworkFeeUSDCents:          aptosLaneNetworkFeeUSDCents,
		V1Params: &lanes.FeeQuoterV1Params{
			MaxNumberOfTokensPerMsg:           aptosLaneMaxNumberOfTokensPerMsg,
			DestGasPerPayloadByteHigh:         aptosLaneDestGasPerPayloadByteHigh,
			DestGasPerPayloadByteThreshold:    aptosLaneDestGasPerPayloadByteThreshold,
			DestDataAvailabilityOverheadGas:   aptosLaneDestDataAvailabilityOverheadGas,
			DestGasPerDataAvailabilityByte:    aptosLaneDestGasPerDataAvailabilityByte,
			DestDataAvailabilityMultiplierBps: aptosLaneDestDataAvailabilityMultiplierBps,
			GasMultiplierWeiPerEth:            aptosLaneGasMultiplierWeiPerEth,
			GasPriceStalenessThreshold:        aptosLaneGasPriceStalenessThreshold,
			EnforceOutOfOrder:                 false,
		},
	}
}

// DefaultAptosLaneGasPrice returns the default USD price (18 decimals) per unit gas
// when Aptos is configured as a destination chain.
func DefaultAptosLaneGasPrice() *big.Int {
	return big.NewInt(aptosLaneDefaultGasPrice)
}

// AptosChainFamilySelectorBytes returns the 4-byte Aptos chain family selector.
func AptosChainFamilySelectorBytes() [4]byte {
	familySelector, _ := hex.DecodeString(AptosFamilySelector)
	var out [4]byte
	copy(out[:], familySelector)
	return out
}

// ToAptosFeeQuoterDestChainConfig converts a lanes.FeeQuoterDestChainConfig to the
// Aptos binding type used by on-chain operations.
func ToAptosFeeQuoterDestChainConfig(fqc lanes.FeeQuoterDestChainConfig) aptos_fee_quoter.DestChainConfig {
	var v1 lanes.FeeQuoterV1Params
	if fqc.V1Params != nil {
		v1 = *fqc.V1Params
	}
	familySelector := make([]byte, 4)
	binary.BigEndian.PutUint32(familySelector, fqc.ChainFamilySelector)

	return aptos_fee_quoter.DestChainConfig{
		IsEnabled:                         fqc.IsEnabled,
		MaxNumberOfTokensPerMsg:           v1.MaxNumberOfTokensPerMsg,
		MaxDataBytes:                      fqc.MaxDataBytes,
		MaxPerMsgGasLimit:                 fqc.MaxPerMsgGasLimit,
		DestGasOverhead:                   fqc.DestGasOverhead,
		DestGasPerPayloadByteBase:         fqc.DestGasPerPayloadByteBase,
		DestGasPerPayloadByteHigh:         v1.DestGasPerPayloadByteHigh,
		DestGasPerPayloadByteThreshold:    v1.DestGasPerPayloadByteThreshold,
		DestDataAvailabilityOverheadGas:   v1.DestDataAvailabilityOverheadGas,
		DestGasPerDataAvailabilityByte:    v1.DestGasPerDataAvailabilityByte,
		DestDataAvailabilityMultiplierBps: v1.DestDataAvailabilityMultiplierBps,
		ChainFamilySelector:               familySelector,
		EnforceOutOfOrder:                 v1.EnforceOutOfOrder,
		DefaultTokenFeeUsdCents:           fqc.DefaultTokenFeeUSDCents,
		DefaultTokenDestGasOverhead:       fqc.DefaultTokenDestGasOverhead,
		DefaultTxGasLimit:                 fqc.DefaultTxGasLimit,
		GasMultiplierWeiPerEth:            v1.GasMultiplierWeiPerEth,
		GasPriceStalenessThreshold:        v1.GasPriceStalenessThreshold,
		NetworkFeeUsdCents:                uint32(fqc.NetworkFeeUSDCents),
	}
}
