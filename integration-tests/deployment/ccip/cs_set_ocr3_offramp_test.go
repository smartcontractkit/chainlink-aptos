package ccip

import (
	"testing"
	"time"

	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	evmdeploy "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/deploy"
	deployops "github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	cs_ccip "github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"
	"github.com/smartcontractkit/chainlink/v2/core/capabilities/ccip/types"

	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"

	_ "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/adapters"
	_ "github.com/smartcontractkit/chainlink-ccip/chains/evm/deployment/v1_6_0/sequences"
)

func TestSetOCR3Offramp(t *testing.T) {
	t.Parallel()

	env, aptosSelector, homeChainSel := newAptosEVMEnvWithOCR3HomeChain(t)

	dReg := deployops.GetRegistry()
	mcmsRegistry := cs_ccip.GetRegistry()

	env, _, err := testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(evmdeploy.SetOCR3Config(dReg, mcmsRegistry), deployops.SetOCR3ConfigArgs{
			HomeChainSel:    homeChainSel,
			RemoteChainSels: []uint64{aptosSelector},
			ConfigType:      utils.ConfigTypeActive,
			MCMS: mcms.Input{
				ValidUntil:     uint32(time.Now().Add(24 * time.Hour).Unix()),
				TimelockDelay:  mcmstypes.NewDuration(time.Second),
				TimelockAction: mcmstypes.TimelockActionSchedule,
			},
		}),
	})
	require.NoError(t, err)

	state, err := stateview.LoadOnchainState(env)
	require.NoError(t, err)

	aptosCCIPAddr := state.AptosChains[aptosSelector].CCIPAddress
	aptosOffRamp := ccip_offramp.Bind(aptosCCIPAddr, env.BlockChains.AptosChains()[aptosSelector].Client)

	ocr3Commit, err := aptosOffRamp.Offramp().LatestConfigDetails(nil, uint8(types.PluginTypeCCIPCommit))
	require.NoError(t, err)
	require.Len(t, ocr3Commit.Signers, 4)
	require.NotEmpty(t, ocr3Commit.ConfigInfo.ConfigDigest)

	ocr3Exec, err := aptosOffRamp.Offramp().LatestConfigDetails(nil, uint8(types.PluginTypeCCIPExec))
	require.NoError(t, err)
	require.Len(t, ocr3Exec.Transmitters, 4)
	require.NotEmpty(t, ocr3Exec.ConfigInfo.ConfigDigest)
}
