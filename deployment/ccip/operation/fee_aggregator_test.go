package operation

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-deployments-framework/pkg/logger"

	aptosmcms "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	aptosstate "github.com/smartcontractkit/chainlink-aptos/deployment/state"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
)

const testCCIPAddress = "0x20f808de3375db34d17cc946ec6b43fc26962f6afa125182dc903359756caf6b"

func mustAddr(t *testing.T, s string) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed(s))
	return a
}

func opTestDeps(t *testing.T, selector uint64) dependency.AptosDeps {
	t.Helper()
	return dependency.AptosDeps{
		AptosChain: cldf_aptos.Chain{Selector: selector},
		CCIPOnChainState: stateview.CCIPOnChainState{
			AptosChains: map[uint64]aptosstate.CCIPChainState{
				selector: {CCIPAddress: mustAddr(t, testCCIPAddress)},
			},
		},
	}
}

func decodeFields(t *testing.T, tx mcmstypes.Transaction) aptosmcms.AdditionalFields {
	t.Helper()
	var f aptosmcms.AdditionalFields
	require.NoError(t, json.Unmarshal(tx.AdditionalFields, &f))
	return f
}

func newBundle() cldf_ops.Bundle {
	return cldf_ops.NewBundle(context.Background, logger.Nop(), cldf_ops.NewMemoryReporter())
}

func TestSetOnRampDynamicConfigOp(t *testing.T) {
	selector := uint64(111)
	feeAgg := mustAddr(t, "0xfee")
	admin := mustAddr(t, "0xad")

	report, err := cldf_ops.ExecuteOperation(newBundle(), SetOnRampDynamicConfigOp, opTestDeps(t, selector),
		SetOnRampDynamicConfigInput{FeeAggregator: feeAgg, AllowlistAdmin: admin})
	require.NoError(t, err)
	require.Len(t, report.Output, 1)

	tx := report.Output[0]
	ccip := mustAddr(t, testCCIPAddress)
	fields := decodeFields(t, tx)
	require.Equal(t, "onramp", fields.ModuleName)
	require.Equal(t, "set_dynamic_config", fields.Function)
	require.Equal(t, ccip.StringLong(), tx.To)

	// Data = BCS(feeAggregator) ++ BCS(allowlistAdmin), each a raw 32-byte address.
	require.Len(t, tx.Data, 64)
	require.Equal(t, feeAgg[:], tx.Data[:32])
	require.Equal(t, admin[:], tx.Data[32:64])
}

func TestWithdrawFeeTokensOp(t *testing.T) {
	selector := uint64(222)
	t1 := mustAddr(t, "0xa1")
	t2 := mustAddr(t, "0xb2")

	report, err := cldf_ops.ExecuteOperation(newBundle(), WithdrawFeeTokensOp, opTestDeps(t, selector),
		WithdrawFeeTokensInput{FeeTokens: []aptos.AccountAddress{t1, t2}})
	require.NoError(t, err)
	require.Len(t, report.Output, 1)

	tx := report.Output[0]
	fields := decodeFields(t, tx)
	require.Equal(t, "onramp", fields.ModuleName)
	require.Equal(t, "withdraw_fee_tokens", fields.Function)

	// Data = BCS(vector<address>): ULEB128 length (2) ++ each 32-byte address.
	require.Len(t, tx.Data, 1+64)
	require.Equal(t, byte(2), tx.Data[0])
	require.Equal(t, t1[:], tx.Data[1:33])
	require.Equal(t, t2[:], tx.Data[33:65])
}
