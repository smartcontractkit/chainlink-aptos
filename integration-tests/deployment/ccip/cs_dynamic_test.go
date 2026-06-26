package ccip

import (
	"math/big"
	"testing"
	"time"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip"
	module_fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	aptoscs "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	aptosconfig "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
	rmnops "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation/rmn"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
	"github.com/smartcontractkit/chainlink-aptos/deployment/subjects"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"
)

func TestDynamicCS_Apply(t *testing.T) {
	t.Parallel()

	env, aptosChainSel := newAptosOnlyEnvWithCCIP(t)

	state, err := stateview.LoadOnchainState(env)
	require.NoError(t, err, "must load onchain state")

	require.Contains(t, env.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyAptos)), aptosChainSel)
	aptosState := state.AptosChains[aptosChainSel]
	aptosChain := env.BlockChains.AptosChains()[aptosChainSel]

	mockTokenAddr := aptosState.CCIPAddress.StringLong()

	registry := operations.NewOperationRegistry(operation.GetAptosOperations()...)
	env.OperationsBundle.OperationRegistry = registry

	defs := []operations.Definition{
		operation.ApplyAllowedOfframpUpdatesOp.Def(),
		operation.UpdateFeeQuoterDestsOp.Def(),
		operation.UpdateFeeQuoterPricesOp.Def(),
		rmnops.CurseMultipleOp.Def(),
	}

	arbSubject := subjects.FamilyAwareSelectorToSubject(
		chain_selectors.ETHEREUM_MAINNET_ARBITRUM_1.Selector,
		chain_selectors.FamilyEVM,
	)
	bscSubject := subjects.FamilyAwareSelectorToSubject(
		chain_selectors.BINANCE_SMART_CHAIN_MAINNET.Selector,
		chain_selectors.FamilyEVM,
	)

	inputs := []any{
		operations.EmptyInput{},
		operation.UpdateFeeQuoterDestsInput{
			Updates: map[uint64]module_fee_quoter.DestChainConfig{
				chain_selectors.ETHEREUM_MAINNET_ARBITRUM_1.EvmChainID: aptosTestDestFeeQuoterConfig(t),
			},
		},
		operation.UpdateFeeQuoterPricesInput{
			TokenPrices: map[string]*big.Int{
				mockTokenAddr: big.NewInt(1000001),
			},
			GasPrices: map[uint64]*big.Int{
				chain_selectors.ETHEREUM_MAINNET_ARBITRUM_1.EvmChainID: big.NewInt(500000),
			},
		},
		rmnops.CurseMultipleInput{
			CCIPAddress: aptosState.CCIPAddress,
			Subjects: [][]byte{
				arbSubject[:],
				bscSubject[:],
			},
		},
	}

	cfg := aptosconfig.DynamicConfig{
		Defs:          defs,
		Inputs:        inputs,
		ChainSelector: aptosChainSel,
		Description:   "Test dynamic changeset with multiple operations",
		MCMSConfig: &cldfproposalutils.TimelockConfig{
			MinDelay:     time.Duration(1) * time.Second,
			MCMSAction:   mcmstypes.TimelockActionSchedule,
			OverrideRoot: false,
		},
	}

	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(aptoscs.DynamicCS{}, cfg),
	})
	require.NoError(t, err, "dynamic changeset should apply successfully")
	env.OperationsBundle.OperationRegistry = operations.NewOperationRegistry(operation.GetAptosOperations()...)

	ccipBind := ccip.Bind(aptosState.CCIPAddress, aptosChain.Client)

	tokenPrice, err := ccipBind.FeeQuoter().GetTokenPrice(nil, aptosState.CCIPAddress)
	require.NoError(t, err)
	require.NotNil(t, tokenPrice)
	require.Equal(t, big.NewInt(1000001), tokenPrice.Value, "token price should be updated")

	ccipOwnerAddress, err := ccipBind.Auth().Owner(nil)
	require.NoError(t, err)

	allowedOfframps, err := ccipBind.Auth().GetAllowedOfframps(nil)
	require.NoError(t, err)

	found := false
	for _, addr := range allowedOfframps {
		if addr == ccipOwnerAddress {
			found = true
			break
		}
	}
	require.True(t, found, "CCIP owner should be in the allowlist after ApplyAllowedOfframpUpdatesOp")

	arbU128Selector := new(big.Int).SetUint64(chain_selectors.ETHEREUM_MAINNET_ARBITRUM_1.Selector)
	bscU128Selector := new(big.Int).SetUint64(chain_selectors.BINANCE_SMART_CHAIN_MAINNET.Selector)
	isCursedU128, err := ccipBind.RMNRemote().IsCursedU128(nil, arbU128Selector)
	require.NoError(t, err)
	require.True(t, isCursedU128, "should be cursed")

	isCursed, err := ccipBind.RMNRemote().IsCursed(nil, arbSubject[:])
	require.NoError(t, err)
	require.True(t, isCursed, "should be cursed")

	defs = []operations.Definition{
		rmnops.UncurseMultipleOp.Def(),
	}

	inputs = []any{
		rmnops.UncurseMultipleInput{
			CCIPAddress: aptosState.CCIPAddress,
			Subjects: [][]byte{
				arbSubject[:],
			},
		},
	}

	cfg = aptosconfig.DynamicConfig{
		Defs:          defs,
		Inputs:        inputs,
		ChainSelector: aptosChainSel,
		Description:   "Test dynamic changeset with uncurse subjects operation",
		MCMSConfig: &cldfproposalutils.TimelockConfig{
			MinDelay:     time.Duration(1) * time.Second,
			MCMSAction:   mcmstypes.TimelockActionSchedule,
			OverrideRoot: false,
		},
	}

	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(aptoscs.DynamicCS{}, cfg),
	})
	require.NoError(t, err, "dynamic changeset should apply successfully")
	env.OperationsBundle.OperationRegistry = operations.NewOperationRegistry(operation.GetAptosOperations()...)

	isCursedU128, err = ccipBind.RMNRemote().IsCursedU128(nil, arbU128Selector)
	require.NoError(t, err)
	require.False(t, isCursedU128, "should not be cursed")

	isCursed, err = ccipBind.RMNRemote().IsCursed(nil, arbSubject[:])
	require.NoError(t, err)
	require.False(t, isCursed, "should not be cursed")

	isCursedU128, err = ccipBind.RMNRemote().IsCursedU128(nil, bscU128Selector)
	require.NoError(t, err)
	require.True(t, isCursedU128, "should be cursed")

	isCursed, err = ccipBind.RMNRemote().IsCursed(nil, bscSubject[:])
	require.NoError(t, err)
	require.True(t, isCursed, "should be cursed")

	defs = []operations.Definition{
		rmnops.CurseMultipleOp.Def(),
	}

	globalSubject := subjects.GlobalCurseSubject()

	inputs = []any{
		rmnops.CurseMultipleInput{
			CCIPAddress: aptosState.CCIPAddress,
			Subjects:    [][]byte{globalSubject[:]},
		},
	}

	cfg = aptosconfig.DynamicConfig{
		Defs:          defs,
		Inputs:        inputs,
		ChainSelector: aptosChainSel,
		Description:   "Test dynamic changeset with global curse operation",
		MCMSConfig: &cldfproposalutils.TimelockConfig{
			MinDelay:     time.Duration(1) * time.Second,
			MCMSAction:   mcmstypes.TimelockActionSchedule,
			OverrideRoot: false,
		},
	}

	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(aptoscs.DynamicCS{}, cfg),
	})
	require.NoError(t, err, "dynamic changeset should apply successfully")

	isCursedGlobal, err := ccipBind.RMNRemote().IsCursedGlobal(nil)
	require.NoError(t, err)
	require.True(t, isCursedGlobal, "should be cursed globally")

	optimismSubject := subjects.FamilyAwareSelectorToSubject(
		chain_selectors.ETHEREUM_MAINNET_OPTIMISM_1.Selector,
		chain_selectors.FamilyEVM,
	)

	isCursed, err = ccipBind.RMNRemote().IsCursed(nil, optimismSubject[:])
	require.NoError(t, err)
	require.True(t, isCursed, "should be cursed")
}
