package ccip

import (
	"testing"
	"time"

	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	aptoscs "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"
)

func TestUpgradeAptosChain_Apply(t *testing.T) {
	t.Parallel()

	env, chainSelector := newAptosOnlyEnvWithCCIP(t)

	cfg := config.UpgradeAptosChainConfig{
		ChainSelector: chainSelector,
		MCMS: &cldfproposalutils.TimelockConfig{
			MinDelay:     time.Second,
			MCMSAction:   mcmstypes.TimelockActionSchedule,
			OverrideRoot: false,
		},
		UpgradeCCIP:    true,
		UpgradeOffRamp: true,
		UpgradeOnRamp:  true,
		UpgradeRouter:  true,
	}

	env, out, err := testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(aptoscs.UpgradeAptosChain{}, cfg),
	})
	require.NoError(t, err)

	proposals := out[0].MCMSTimelockProposals
	require.Len(t, proposals, 1)
	require.Len(t, proposals[0].Operations, 8)
}
