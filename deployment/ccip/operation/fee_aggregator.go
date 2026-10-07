package operation

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
)

// FeeAggregatorOperations exposes the OnRamp fee-aggregator operations to the dynamic
// sequence registry (GetAptosOperations). Both return []mcmstypes.Transaction.
var FeeAggregatorOperations = []*operations.Operation[any, any, any]{
	SetOnRampDynamicConfigOp.AsUntypedRelaxed(),
	WithdrawFeeTokensOp.AsUntypedRelaxed(),
}

// SetOnRampDynamicConfigInput carries both fields of the OnRamp DynamicConfig. The Move
// entry function set_dynamic_config writes both, so a caller that only wants to change
// the fee aggregator must read the current config first and pass the existing
// AllowlistAdmin to avoid clobbering it.
type SetOnRampDynamicConfigInput struct {
	FeeAggregator  aptos.AccountAddress
	AllowlistAdmin aptos.AccountAddress
}

var SetOnRampDynamicConfigOp = operations.NewOperation(
	"set-onramp-dynamic-config-op",
	Version1_0_0,
	"Sets the OnRamp dynamic config (fee aggregator + allowlist admin)",
	setOnRampDynamicConfig,
)

func setOnRampDynamicConfig(b operations.Bundle, deps dependency.AptosDeps, in SetOnRampDynamicConfigInput) ([]mcmstypes.Transaction, error) {
	aptosState := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector]
	ccipAddress := aptosState.CCIPAddress
	onrampBind := ccip_onramp.Bind(ccipAddress, deps.AptosChain.Client)

	moduleInfo, function, _, args, err := onrampBind.Onramp().Encoder().SetDynamicConfig(in.FeeAggregator, in.AllowlistAdmin)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SetDynamicConfig for OnRamp: %w", err)
	}
	tx, err := utils.GenerateMCMSTx(ccipAddress, moduleInfo, function, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	return []mcmstypes.Transaction{tx}, nil
}

// WithdrawFeeTokensInput lists the fee token (fungible asset) addresses to sweep to the
// configured fee aggregator. The Move entry function withdraws the full balance of each
// token; there is no per-token amount.
type WithdrawFeeTokensInput struct {
	FeeTokens []aptos.AccountAddress
}

var WithdrawFeeTokensOp = operations.NewOperation(
	"withdraw-fee-tokens-op",
	Version1_0_0,
	"Withdraws accumulated fee token balances to the OnRamp fee aggregator",
	withdrawFeeTokens,
)

func withdrawFeeTokens(b operations.Bundle, deps dependency.AptosDeps, in WithdrawFeeTokensInput) ([]mcmstypes.Transaction, error) {
	aptosState := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector]
	ccipAddress := aptosState.CCIPAddress
	onrampBind := ccip_onramp.Bind(ccipAddress, deps.AptosChain.Client)

	moduleInfo, function, _, args, err := onrampBind.Onramp().Encoder().WithdrawFeeTokens(in.FeeTokens)
	if err != nil {
		return nil, fmt.Errorf("failed to encode WithdrawFeeTokens for OnRamp: %w", err)
	}
	tx, err := utils.GenerateMCMSTx(ccipAddress, moduleInfo, function, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	return []mcmstypes.Transaction{tx}, nil
}
