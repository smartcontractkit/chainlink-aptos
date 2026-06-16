package ccip

import (
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	aptoscs "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
)

func TestMigrateOnRampDestChainConfigsToV2_Apply(t *testing.T) {
	t.Parallel()

	env, chainSelector := newAptosOnlyEnvWithCCIP(t)

	state, err := stateview.LoadOnchainState(env)
	require.NoError(t, err)
	aptosState := state.AptosChains[chainSelector]

	destSelector := chain_selectors.ETHEREUM_MAINNET.Selector
	cfg := config.MigrateOnRampDestChainConfigsToV2Config{
		ChainSelector:         chainSelector,
		DestChainSelectors:    []uint64{destSelector},
		RouterModuleAddresses: []aptos.AccountAddress{aptosState.CCIPAddress},
		MCMS: &cldfproposalutils.TimelockConfig{
			MinDelay:     time.Second,
			MCMSAction:   mcmstypes.TimelockActionSchedule,
			OverrideRoot: false,
		},
	}

	cs := aptoscs.MigrateOnRampDestChainConfigsToV2{}
	require.NoError(t, cs.VerifyPreconditions(env, cfg))

	env.OperationsBundle.OperationRegistry = operations.NewOperationRegistry(operation.GetAptosOperations()...)

	out, err := cs.Apply(env, cfg)
	require.NoError(t, err)

	proposals := out.MCMSTimelockProposals
	require.Len(t, proposals, 1)
	require.Len(t, proposals[0].Operations, 1)
}
