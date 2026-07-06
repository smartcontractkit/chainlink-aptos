package adapters

import (
	"fmt"
	"math/big"

	"github.com/Masterminds/semver/v3"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	aptos_fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	aptos_router "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router/router"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/v1_6"
	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"
)

// AptosLaneAdapter implements lanes.LaneAdapter for Aptos chains.
type AptosLaneAdapter struct{}

var (
	_ lanes.LaneAdapter           = &AptosLaneAdapter{}
	_ lanes.ChainMetadataProvider = &AptosLaneAdapter{}
)

// Aptos CCIP uses a single on-chain module account for OnRamp, OffRamp, Router, and FeeQuoter.
func (a *AptosLaneAdapter) GetOnRampAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return getCCIPAccountBytes(ds, chainSelector)
}

func (a *AptosLaneAdapter) GetOffRampAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return getCCIPAccountBytes(ds, chainSelector)
}

func (a *AptosLaneAdapter) GetFQAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return getCCIPAccountBytes(ds, chainSelector)
}

func (a *AptosLaneAdapter) GetRouterAddress(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return getCCIPAccountBytes(ds, chainSelector)
}

func (a *AptosLaneAdapter) GetFeeQuoterDestChainConfig() lanes.FeeQuoterDestChainConfig {
	return v1_6.DefaultAptosLaneFeeQuoterDestChainConfig()
}

func (a *AptosLaneAdapter) GetDefaultGasPrice() *big.Int {
	return v1_6.DefaultAptosLaneGasPrice()
}

func (a *AptosLaneAdapter) GetChainFamilySelector() [4]byte {
	return v1_6.AptosChainFamilySelectorBytes()
}

func (a *AptosLaneAdapter) ConfigureLaneLegAsSource() *cldf_ops.Sequence[lanes.UpdateLanesInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return ConfigureLaneLegAsSource
}

func (a *AptosLaneAdapter) ConfigureLaneLegAsDest() *cldf_ops.Sequence[lanes.UpdateLanesInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return ConfigureLaneLegAsDest
}

func (a *AptosLaneAdapter) DisableRemoteChain() *cldf_ops.Sequence[lanes.DisableRemoteChainInput, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("DisableRemoteChain not implemented for Aptos")
}

func appendApplyAllowedOfframpUpdates(b cldf_ops.Bundle, output *sequences.OnChainOutput, chainSelector uint64, deps dependency.AptosDeps) error {
	allowedReport, err := cldf_ops.ExecuteOperation(b, operation.ApplyAllowedOfframpUpdatesOp, deps, operations.EmptyInput{})
	if err != nil {
		return fmt.Errorf("apply allowed offramp updates: %w", err)
	}
	appendBatchOp(output, chainSelector, []mcmstypes.Transaction{allowedReport.Output})
	return nil
}

var ConfigureLaneLegAsSource = cldf_ops.NewSequence(
	"aptos/sequences/ccip/tooling-api/configure-lane-leg-as-source",
	semver.MustParse("1.6.0"),
	"Configures lane leg as source on CCIP 1.6.0",
	func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, input lanes.UpdateLanesInput) (sequences.OnChainOutput, error) {
		chainSelector := input.Source.Selector
		chain := chains.AptosChains()[chainSelector]
		deps := buildAptosDeps(chain, chainSelector, input.Source.OnRamp)

		var result sequences.OnChainOutput
		isEnabled := !input.IsDisabled

		fqReport, err := cldf_ops.ExecuteOperation(b, operation.UpdateFeeQuoterDestsOp, deps, operation.UpdateFeeQuoterDestsInput{
			Updates: map[uint64]aptos_fee_quoter.DestChainConfig{
				input.Dest.Selector: v1_6.ToAptosFeeQuoterDestChainConfig(input.Dest.FeeQuoterDestChainConfig),
			},
		})
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("update fee quoter dests: %w", err)
		}
		appendBatchOp(&result, chainSelector, fqReport.Output)

		onRampReport, err := cldf_ops.ExecuteOperation(b, operation.UpdateOnRampDestsOp, deps, operation.UpdateOnRampDestsInput{
			Updates: map[uint64]v1_6.OnRampDestinationUpdate{
				input.Dest.Selector: {
					IsEnabled:        isEnabled,
					TestRouter:       input.TestRouter,
					AllowListEnabled: input.Dest.AllowListEnabled,
				},
			},
		})
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("update onramp dests: %w", err)
		}
		appendBatchOp(&result, chainSelector, onRampReport.Output)

		// Fee quoter price updates require the CCIP owner on the offramp allowlist.
		if err := appendApplyAllowedOfframpUpdates(b, &result, chainSelector, deps); err != nil {
			return sequences.OnChainOutput{}, err
		}

		priceReport, err := cldf_ops.ExecuteOperation(b, operation.UpdateFeeQuoterPricesOp, deps, operation.UpdateFeeQuoterPricesInput{
			TokenPrices: input.Source.TokenPrices,
			GasPrices: map[uint64]*big.Int{
				input.Dest.Selector: input.Dest.GasPrice,
			},
		})
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("update fee quoter prices: %w", err)
		}
		appendBatchOp(&result, chainSelector, priceReport.Output)

		onRampVersion := input.ExtraConfigs.OnRampVersion
		if onRampVersion == nil {
			onRampVersion = []byte{1, 6, 0}
		}
		routerReport, err := cldf_ops.ExecuteOperation(b, operation.UpdateRouterOp, deps, operation.UpdateRouterDestInput{
			Updates: []aptos_router.OnRampSet{{
				DestChainSelector: input.Dest.Selector,
				OnRampVersion:     onRampVersion,
			}},
		})
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("update router: %w", err)
		}
		appendBatchOp(&result, chainSelector, []mcmstypes.Transaction{routerReport.Output})

		return result, nil
	},
)

var ConfigureLaneLegAsDest = cldf_ops.NewSequence(
	"aptos/sequences/ccip/tooling-api/configure-lane-leg-as-dest",
	semver.MustParse("1.6.0"),
	"Configures lane leg as dest on CCIP 1.6.0",
	func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, input lanes.UpdateLanesInput) (sequences.OnChainOutput, error) {
		chainSelector := input.Dest.Selector
		chain := chains.AptosChains()[chainSelector]
		deps := buildAptosDeps(chain, chainSelector, input.Dest.OffRamp)

		var result sequences.OnChainOutput
		isEnabled := !input.IsDisabled

		offRampReport, err := cldf_ops.ExecuteOperation(b, operation.UpdateOffRampSourcesOp, deps, operation.UpdateOffRampSourcesInput{
			Updates: map[uint64]v1_6.OffRampSourceUpdate{
				input.Source.Selector: {
					IsEnabled:                 isEnabled,
					TestRouter:                input.TestRouter,
					IsRMNVerificationDisabled: !input.Source.RMNVerificationEnabled,
					OnRamp:                    input.Source.OnRamp,
				},
			},
		})
		if err != nil {
			return sequences.OnChainOutput{}, fmt.Errorf("update offramp sources: %w", err)
		}
		appendBatchOp(&result, chainSelector, offRampReport.Output)

		return result, nil
	},
)

func appendBatchOp(output *sequences.OnChainOutput, chainSelector uint64, txs []mcmstypes.Transaction) {
	if len(txs) == 0 {
		return
	}
	output.BatchOps = append(output.BatchOps, mcmstypes.BatchOperation{
		ChainSelector: mcmstypes.ChainSelector(chainSelector),
		Transactions:  txs,
	})
}
