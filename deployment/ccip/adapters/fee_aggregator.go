package adapters

import (
	"fmt"

	"github.com/Masterminds/semver/v3"
	"github.com/aptos-labs/aptos-go-sdk"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccip/deployment/fees"
	datastore_utils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"

	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	module_onramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp/onramp"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
)

// FeeAggregatorAdapter implements fees.FeeAggregatorAdapter for Aptos. On Aptos the fee
// aggregator is stored in the OnRamp DynamicConfig, the direct analog of EVM 1.6.
type FeeAggregatorAdapter struct{}

var _ fees.FeeAggregatorAdapter = (*FeeAggregatorAdapter)(nil)

// onrampDynamicConfigReader reads the OnRamp DynamicConfig. It is a package var so tests
// can stub the on-chain read without a live Aptos client.
var onrampDynamicConfigReader = func(ccipAddress aptos.AccountAddress, client aptos.AptosRpcClient) (module_onramp.DynamicConfig, error) {
	return ccip_onramp.Bind(ccipAddress, client).Onramp().GetDynamicConfig(nil)
}

// resolveAptosCCIPAddress returns the Aptos CCIP module account address for the chain.
// Aptos uses a single module account for OnRamp/OffRamp/Router/FeeQuoter, so by default
// it is resolved from the datastore; an explicit single contract ref overrides it.
func resolveAptosCCIPAddress(e cldf.Environment, chainSelector uint64, contracts []datastore.AddressRef) (aptos.AccountAddress, error) {
	var (
		ccipBytes []byte
		err       error
	)
	switch len(contracts) {
	case 0:
		ccipBytes, err = getCCIPAccountBytes(e.DataStore, chainSelector)
	case 1:
		ccipBytes, err = datastore_utils.FindAndFormatRef(e.DataStore, contracts[0], chainSelector, accountAddressToBytes)
	default:
		return aptos.AccountAddress{}, fmt.Errorf("aptos fee aggregator adapter supports exactly one contract ref, got %d", len(contracts))
	}
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var addr aptos.AccountAddress
	copy(addr[:], ccipBytes)
	return addr, nil
}

func (a *FeeAggregatorAdapter) GetFeeAggregator(e cldf.Environment, chainSelector uint64) (string, error) {
	chain, ok := e.BlockChains.AptosChains()[chainSelector]
	if !ok {
		return "", fmt.Errorf("aptos chain with selector %d not defined", chainSelector)
	}
	ccipAddr, err := resolveAptosCCIPAddress(e, chainSelector, nil)
	if err != nil {
		return "", err
	}
	dc, err := onrampDynamicConfigReader(ccipAddr, chain.Client)
	if err != nil {
		return "", fmt.Errorf("failed to read OnRamp dynamic config on chain %d: %w", chainSelector, err)
	}
	return dc.FeeAggregator.StringLong(), nil
}

func (a *FeeAggregatorAdapter) SetFeeAggregator(e cldf.Environment) *cldf_ops.Sequence[fees.FeeAggregatorForChain, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return cldf_ops.NewSequence(
		"aptos/sequences/ccip/tooling-api/set-fee-aggregator",
		semver.MustParse("1.6.0"),
		"Sets the fee aggregator on the Aptos CCIP 1.6.0 OnRamp dynamic config",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, input fees.FeeAggregatorForChain) (sequences.OnChainOutput, error) {
			var result sequences.OnChainOutput

			chain, ok := chains.AptosChains()[input.ChainSelector]
			if !ok {
				return result, fmt.Errorf("aptos chain with selector %d not defined", input.ChainSelector)
			}

			var feeAggregator aptos.AccountAddress
			if err := feeAggregator.ParseStringRelaxed(input.FeeAggregator); err != nil {
				return result, fmt.Errorf("invalid fee aggregator address %q: %w", input.FeeAggregator, err)
			}

			ccipAddr, err := resolveAptosCCIPAddress(e, input.ChainSelector, input.Contracts)
			if err != nil {
				return result, err
			}

			// set_dynamic_config writes both fields; preserve the current allowlist admin.
			current, err := onrampDynamicConfigReader(ccipAddr, chain.Client)
			if err != nil {
				return result, fmt.Errorf("failed to read OnRamp dynamic config on chain %d: %w", input.ChainSelector, err)
			}

			deps := buildAptosDeps(chain, input.ChainSelector, ccipAddr[:])
			report, err := cldf_ops.ExecuteOperation(b, operation.SetOnRampDynamicConfigOp, deps, operation.SetOnRampDynamicConfigInput{
				FeeAggregator:  feeAggregator,
				AllowlistAdmin: current.AllowlistAdmin,
			})
			if err != nil {
				return result, fmt.Errorf("failed to set OnRamp dynamic config on chain %d: %w", input.ChainSelector, err)
			}
			appendBatchOp(&result, input.ChainSelector, report.Output)
			return result, nil
		},
	)
}

func (a *FeeAggregatorAdapter) WithdrawFeeTokens(e cldf.Environment) *cldf_ops.Sequence[fees.WithdrawFeeTokensForChain, sequences.OnChainOutput, cldf_chain.BlockChains] {
	return cldf_ops.NewSequence(
		"aptos/sequences/ccip/tooling-api/withdraw-fee-tokens",
		semver.MustParse("1.6.0"),
		"Withdraws accumulated fee token balances to the fee aggregator on the Aptos CCIP 1.6.0 OnRamp",
		func(b cldf_ops.Bundle, chains cldf_chain.BlockChains, input fees.WithdrawFeeTokensForChain) (sequences.OnChainOutput, error) {
			var result sequences.OnChainOutput

			chain, ok := chains.AptosChains()[input.ChainSelector]
			if !ok {
				return result, fmt.Errorf("aptos chain with selector %d not defined", input.ChainSelector)
			}
			if len(input.FeeTokens) == 0 {
				return result, fmt.Errorf("no fee tokens provided for chain %d", input.ChainSelector)
			}

			feeTokens := make([]aptos.AccountAddress, 0, len(input.FeeTokens))
			for _, ft := range input.FeeTokens {
				// Amount is intentionally ignored: withdraw_fee_tokens sweeps the full balance.
				var token aptos.AccountAddress
				if err := token.ParseStringRelaxed(ft.Token); err != nil {
					return result, fmt.Errorf("invalid fee token address %q on chain %d: %w", ft.Token, input.ChainSelector, err)
				}
				feeTokens = append(feeTokens, token)
			}

			ccipAddr, err := resolveAptosCCIPAddress(e, input.ChainSelector, input.Contracts)
			if err != nil {
				return result, err
			}

			// withdraw_fee_tokens aborts on-chain if the fee aggregator is unset (@0x0);
			// fail early with a clearer message.
			current, err := onrampDynamicConfigReader(ccipAddr, chain.Client)
			if err != nil {
				return result, fmt.Errorf("failed to read OnRamp dynamic config on chain %d: %w", input.ChainSelector, err)
			}
			if current.FeeAggregator == (aptos.AccountAddress{}) {
				return result, fmt.Errorf("fee aggregator is not set on OnRamp (chain %d); set it before withdrawing fee tokens", input.ChainSelector)
			}

			deps := buildAptosDeps(chain, input.ChainSelector, ccipAddr[:])
			report, err := cldf_ops.ExecuteOperation(b, operation.WithdrawFeeTokensOp, deps, operation.WithdrawFeeTokensInput{
				FeeTokens: feeTokens,
			})
			if err != nil {
				return result, fmt.Errorf("failed to withdraw fee tokens on chain %d: %w", input.ChainSelector, err)
			}
			appendBatchOp(&result, input.ChainSelector, report.Output)
			return result, nil
		},
	)
}
