package ccip

import (
	"math/big"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/aptos-labs/aptos-go-sdk"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"

	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/sequences"
	deployops "github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	cs_ccip "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	_ "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/adapters"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"
)

func TestUpdateAptosLanes(t *testing.T) {
	t.Parallel()

	env, aptosSelector := newAptosEVMEnvWithCCIP(t, 2)

	evmSelectors := env.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyEVM))
	require.Len(t, evmSelectors, 2)
	evmSelector1 := evmSelectors[0]
	evmSelector2 := evmSelectors[1]

	toolingAPIVersion := semver.MustParse("1.6.0")
	dReg := deployops.GetRegistry()

	evmChainCfg := deployops.ContractDeploymentConfigPerChain{
		Version:                                 toolingAPIVersion,
		MaxFeeJuelsPerMsg:                       big.NewInt(0).Mul(big.NewInt(200), big.NewInt(1e18)),
		TokenPriceStalenessThreshold:            uint32(24 * 60 * 60),
		LinkPremiumMultiplier:                   9e17,
		NativeTokenPremiumMultiplier:            1e18,
		PermissionLessExecutionThresholdSeconds: uint32((20 * time.Minute).Seconds()),
		GasForCallExactCheck:                    uint16(5000),
	}

	env, _, err := testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(deployops.DeployContracts(dReg), deployops.ContractDeploymentConfig{
			MCMS: mcms.Input{},
			Chains: map[uint64]deployops.ContractDeploymentConfigPerChain{
				evmSelector1: evmChainCfg,
				evmSelector2: evmChainCfg,
			},
		}),
	})
	require.NoError(t, err)

	aptosDefinition := lanes.ChainDefinition{
		Selector: aptosSelector,
		GasPrice: big.NewInt(1e17),
		TokenPrices: map[string]*big.Int{
			shared.AptosAPTAddress: big.NewInt(1e18),
		},
		RMNVerificationEnabled: false,
		AllowListEnabled:       false,
	}

	evmDefinition1 := lanes.ChainDefinition{
		Selector:               evmSelector1,
		GasPrice:               big.NewInt(1e17),
		RMNVerificationEnabled: false,
		AllowListEnabled:       false,
	}

	evmDefinition2 := lanes.ChainDefinition{
		Selector:               evmSelector2,
		GasPrice:               big.NewInt(1e17),
		RMNVerificationEnabled: false,
		AllowListEnabled:       false,
	}

	lanesRegistry := lanes.GetLaneAdapterRegistry()
	mcmsRegistry := cs_ccip.GetRegistry()

	mcmsInput := mcms.Input{
		ValidUntil:     uint32(time.Now().Add(24 * time.Hour).Unix()),
		TimelockDelay:  mcmstypes.NewDuration(time.Second),
		TimelockAction: mcmstypes.TimelockActionSchedule,
	}

	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(lanes.ConnectChains(lanesRegistry, mcmsRegistry), lanes.ConnectChainsConfig{
			MCMS: mcmsInput,
			Lanes: []lanes.LaneConfig{
				{
					Version: toolingAPIVersion,
					ChainA:  aptosDefinition,
					ChainB:  evmDefinition1,
					ExtraConfigs: lanes.ExtraConfigs{
						OnRampVersion: []byte{1, 6, 1},
					},
				},
				{
					Version: toolingAPIVersion,
					ChainA:  aptosDefinition,
					ChainB:  evmDefinition2,
				},
			},
		}),
	})
	require.NoError(t, err)

	state, err := stateview.LoadOnchainState(env)
	require.NoError(t, err)

	aptosCCIPAddr := state.AptosChains[aptosSelector].CCIPAddress
	aptosOnRamp := ccip_onramp.Bind(aptosCCIPAddr, env.BlockChains.AptosChains()[aptosSelector].Client)
	aptosOffRamp := ccip_offramp.Bind(aptosCCIPAddr, env.BlockChains.AptosChains()[aptosSelector].Client)
	aptosRouter := ccip_router.Bind(aptosCCIPAddr, env.BlockChains.AptosChains()[aptosSelector].Client)

	dynCfg, err := aptosOffRamp.Offramp().GetDynamicConfig(&bind.CallOpts{})
	require.NoError(t, err)
	require.Positive(t, dynCfg.PermissionlessExecutionThresholdSeconds)

	isSupported, err := aptosOnRamp.Onramp().IsChainSupported(&bind.CallOpts{}, evmSelector1)
	require.NoError(t, err)
	require.True(t, isSupported)

	_, _, router, routerState, err := aptosOnRamp.Onramp().GetDestChainConfigV2(&bind.CallOpts{}, evmSelector1)
	require.NoError(t, err)
	require.NotEqual(t, aptos.AccountAddress{}, router)
	require.NotEqual(t, aptos.AccountAddress{}, routerState)

	_, _, router2, routerState2, err := aptosOnRamp.Onramp().GetDestChainConfigV2(&bind.CallOpts{}, evmSelector2)
	require.NoError(t, err)
	require.NotEqual(t, aptos.AccountAddress{}, router2)
	require.NotEqual(t, aptos.AccountAddress{}, routerState2)

	versions, err := aptosRouter.Router().GetOnRampVersions(&bind.CallOpts{}, []uint64{evmSelector1, evmSelector2})
	require.NoError(t, err)
	require.ElementsMatch(t, versions, [][]byte{{1, 6, 1}, {1, 6, 0}})

	aptosCCIP := ccip.Bind(aptosCCIPAddr, env.BlockChains.AptosChains()[aptosSelector].Client)
	price, err := aptosCCIP.FeeQuoter().GetTokenPrice(&bind.CallOpts{}, MustParseAddress(t, "0xa"))
	require.NoError(t, err)
	require.Equal(t, big.NewInt(1e18), price.Value)
}
