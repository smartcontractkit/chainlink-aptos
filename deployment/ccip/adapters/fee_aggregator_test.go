package adapters

import (
	"context"
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf_datastore "github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-deployments-framework/pkg/logger"

	"github.com/smartcontractkit/chainlink-ccip/deployment/fees"

	module_onramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp/onramp"
	aptosccip "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
)

const testCCIPAddress = "0x20f808de3375db34d17cc946ec6b43fc26962f6afa125182dc903359756caf6b"

func mustAddr(t *testing.T, s string) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed(s))
	return a
}

// stubReader replaces the on-chain dynamic-config read for the duration of a test.
func stubReader(dc module_onramp.DynamicConfig, err error) func() {
	prev := onrampDynamicConfigReader
	onrampDynamicConfigReader = func(_ aptos.AccountAddress, _ aptos.AptosRpcClient) (module_onramp.DynamicConfig, error) {
		return dc, err
	}
	return func() { onrampDynamicConfigReader = prev }
}

func adapterEnv(t *testing.T, selector uint64) cldf.Environment {
	t.Helper()
	ds := cldf_datastore.NewMemoryDataStore()
	require.NoError(t, ds.Addresses().Add(cldf_datastore.AddressRef{
		ChainSelector: selector,
		Address:       testCCIPAddress,
		Type:          cldf_datastore.ContractType(shared.AptosCCIPType),
		Version:       &aptosccip.Version1_6_0,
	}))
	chain := cldf_aptos.Chain{Selector: selector}
	return cldf.Environment{
		DataStore:   ds.Seal(),
		BlockChains: cldf_chain.NewBlockChainsFromSlice([]cldf_chain.BlockChain{chain}),
	}
}

func newBundle() cldf_ops.Bundle {
	return cldf_ops.NewBundle(context.Background, logger.Nop(), cldf_ops.NewMemoryReporter())
}

func TestGetFeeAggregator(t *testing.T) {
	feeAgg := mustAddr(t, "0xfee")
	defer stubReader(module_onramp.DynamicConfig{FeeAggregator: feeAgg, AllowlistAdmin: mustAddr(t, "0xdead")}, nil)()

	got, err := (&FeeAggregatorAdapter{}).GetFeeAggregator(adapterEnv(t, 1), 1)
	require.NoError(t, err)
	require.Equal(t, feeAgg.StringLong(), got)
}

func TestSetFeeAggregatorPreservesAllowlistAdmin(t *testing.T) {
	admin := mustAddr(t, "0xdead")
	defer stubReader(module_onramp.DynamicConfig{FeeAggregator: mustAddr(t, "0x01d"), AllowlistAdmin: admin}, nil)()

	env := adapterEnv(t, 1)
	newFeeAgg := mustAddr(t, "0xfee")
	seq := (&FeeAggregatorAdapter{}).SetFeeAggregator(env)
	report, err := cldf_ops.ExecuteSequence(newBundle(), seq, env.BlockChains, fees.FeeAggregatorForChain{
		ChainSelector: 1,
		FeeAggregator: newFeeAgg.StringLong(),
	})
	require.NoError(t, err)
	require.Len(t, report.Output.BatchOps, 1)
	require.Len(t, report.Output.BatchOps[0].Transactions, 1)

	// Data = BCS(newFeeAggregator) ++ BCS(preserved allowlistAdmin).
	data := report.Output.BatchOps[0].Transactions[0].Data
	require.Len(t, data, 64)
	require.Equal(t, newFeeAgg[:], data[:32])
	require.Equal(t, admin[:], data[32:64])
}

func TestWithdrawFeeTokensErrorsWhenAggregatorUnset(t *testing.T) {
	defer stubReader(module_onramp.DynamicConfig{}, nil)() // zero fee aggregator

	env := adapterEnv(t, 1)
	token := mustAddr(t, "0xa1")
	seq := (&FeeAggregatorAdapter{}).WithdrawFeeTokens(env)
	_, err := cldf_ops.ExecuteSequence(newBundle(), seq, env.BlockChains, fees.WithdrawFeeTokensForChain{
		ChainSelector: 1,
		FeeTokens:     []fees.FeeTokenWithdrawal{{Token: token.StringLong()}},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "fee aggregator is not set")
}

func TestWithdrawFeeTokensIgnoresAmountAndSweepsAll(t *testing.T) {
	defer stubReader(module_onramp.DynamicConfig{FeeAggregator: mustAddr(t, "0xfee")}, nil)()

	env := adapterEnv(t, 1)
	t1 := mustAddr(t, "0xa1")
	t2 := mustAddr(t, "0xb2")
	seq := (&FeeAggregatorAdapter{}).WithdrawFeeTokens(env)
	report, err := cldf_ops.ExecuteSequence(newBundle(), seq, env.BlockChains, fees.WithdrawFeeTokensForChain{
		ChainSelector: 1,
		FeeTokens: []fees.FeeTokenWithdrawal{
			{Token: t1.StringLong(), Amount: big.NewInt(5)}, // amount must be ignored
			{Token: t2.StringLong()},
		},
	})
	require.NoError(t, err)
	require.Len(t, report.Output.BatchOps, 1)
	require.Len(t, report.Output.BatchOps[0].Transactions, 1)

	// Data = BCS(vector<address>{t1, t2}): length 2 ++ two 32-byte addresses.
	data := report.Output.BatchOps[0].Transactions[0].Data
	require.Len(t, data, 1+64)
	require.Equal(t, byte(2), data[0])
	require.Equal(t, t1[:], data[1:33])
	require.Equal(t, t2[:], data[33:65])
}
