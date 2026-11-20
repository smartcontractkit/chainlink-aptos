package cre_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	ocrtypes "github.com/smartcontractkit/libocr/offchainreporting2/types"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldflogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	cldftesthelpers "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils/testhelpers"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/runtime"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink/deployment"
	jdtest "github.com/smartcontractkit/chainlink/deployment/environment/test"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	mcmsbind "github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
	"github.com/smartcontractkit/chainlink-aptos/deployment/cre"
)

// Test_ForwarderGovernance runs the whole CRE forwarder governance lifecycle on an Aptos
// localnet, the way the data-feeds-cre-staging pipelines will: deployer-owned forwarders are
// configured directly, then handed to a dedicated MCMS through the forwarder_mcms_adapter, and
// configured through MCMS proposals from then on.
func Test_ForwarderGovernance(t *testing.T) {
	selector := chain_selectors.APTOS_LOCALNET.Selector
	rt, err := runtime.New(t.Context(), runtime.WithEnvOpts(
		environment.WithAptosContainer(t, []uint64{selector}),
		environment.WithLogger(cldflogger.Test(t)),
	))
	require.NoError(t, err)
	env := rt.Environment()
	chain := env.BlockChains.AptosChains()[selector]
	deployer := chain.DeployerSigner.AccountAddress()

	// ===== 0. Forwarders, deployed and owned by the deployer =====
	env, _ = apply(t, env, cre.DeployForwarders{}, cre.DeployForwardersConfig{ChainSelector: selector})
	primaryAddr := refAddress(t, env, cre.AptosForwarderType, string(cre.ZoneA))
	secondaryAddr := refAddress(t, env, cre.AptosForwarderType, string(cre.ZoneB))
	primary := platform.Bind(primaryAddr, chain.Client)
	secondary := platform_secondary.Bind(secondaryAddr, chain.Client)
	for _, f := range []interface {
		GetOwner(*bind.CallOpts) (aptos.AccountAddress, error)
	}{primary.Forwarder(), secondary.Forwarder()} {
		owner, err := f.GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, deployer, owner)
	}

	t.Run("forwarders cannot be deployed twice", func(t *testing.T) {
		err := cre.DeployForwarders{}.VerifyPreconditions(env, cre.DeployForwardersConfig{ChainSelector: selector, Zones: []cre.Zone{cre.ZoneB}})
		require.ErrorContains(t, err, "datastore conflict")
	})

	// ===== DON nodes in a test job distributor =====
	donA, keysA := withDON(t, &env, selector, "zone-a", 4)
	donB, keysB := withDON(t, &env, selector, "zone-b", 7)

	timelock := &cldfproposalutils.TimelockConfig{MinDelay: time.Second, MCMSAction: mcmstypes.TimelockActionSchedule}

	t.Run("direct set_config while the deployer owns the forwarder", func(t *testing.T) {
		env, _ = apply(t, env, cre.SetForwarderConfig{}, cre.SetForwarderConfigConfig{
			ChainSelector: selector, Zone: cre.ZoneA,
			DON: cre.DON{ID: 1, ConfigVersion: 1, F: 1, NodeIDs: donA},
		})
		require.Equal(t, keysA, configOracles(t, chain, primaryAddr, contracts.Platform, 1, 1))
	})

	t.Run("adapter cannot be deployed before the MCMS", func(t *testing.T) {
		err := cre.DeployForwarderAdapter{}.VerifyPreconditions(env, cre.DeployForwarderAdapterConfig{ChainSelector: selector, TimelockConfig: *timelock})
		require.ErrorContains(t, err, "AptosManyChainMultisig")
	})

	// ===== 1. CRE MCMS =====
	var mcmsAddr aptos.AccountAddress
	require.True(t, t.Run("deploy CRE MCMS", func(t *testing.T) {
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.DeployCREMCMS{}, cre.DeployCREMCMSConfig{
			ChainSelector: selector,
			MCMS: cldfproposalutils.MCMSWithTimelockConfig{
				Canceller:        cldftesthelpers.SingleGroupMCMS(t),
				Bypasser:         cldftesthelpers.SingleGroupMCMS(t),
				Proposer:         cldftesthelpers.SingleGroupMCMS(t),
				TimelockMinDelay: big.NewInt(0),
			},
			TimelockConfig: *timelock,
		})
		mcmsAddr = refAddress(t, env, cre.AptosMCMSType, cre.DefaultQualifier)

		// Until its proposal executes, MCMS does not own itself and cannot publish the adapter.
		err := cre.DeployForwarderAdapter{}.VerifyPreconditions(env, cre.DeployForwarderAdapterConfig{ChainSelector: selector, TimelockConfig: *timelock})
		require.ErrorContains(t, err, "does not own itself")

		execute(t, env, out)
		owner, err := mcmsbind.Bind(mcmsAddr, chain.Client).MCMSAccount().Owner(nil)
		require.NoError(t, err)
		require.Equal(t, mcmsAddr, owner, "MCMS must own itself")
	}))

	t.Run("a second CRE MCMS under the same qualifier is refused", func(t *testing.T) {
		err := cre.DeployCREMCMS{}.VerifyPreconditions(env, cre.DeployCREMCMSConfig{
			ChainSelector: selector,
			MCMS: cldfproposalutils.MCMSWithTimelockConfig{
				Canceller: cldftesthelpers.SingleGroupMCMS(t), Bypasser: cldftesthelpers.SingleGroupMCMS(t),
				Proposer: cldftesthelpers.SingleGroupMCMS(t), TimelockMinDelay: big.NewInt(0),
			},
		})
		require.ErrorContains(t, err, "datastore conflict")
	})

	// ===== 2. Adapter, published by MCMS =====
	var adapterAddr, adapterOwner aptos.AccountAddress
	require.True(t, t.Run("deploy adapter through MCMS", func(t *testing.T) {
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.DeployForwarderAdapter{}, cre.DeployForwarderAdapterConfig{ChainSelector: selector, TimelockConfig: *timelock})
		execute(t, env, out)
		adapterAddr = refAddress(t, env, cre.AptosForwarderMcmsAdapterType, cre.DefaultQualifier)
		adapterOwner = refAddress(t, env, cre.AptosForwarderMcmsAdapterOwnerType, cre.DefaultQualifier)

		owned, err := mcmsbind.Bind(mcmsAddr, chain.Client).MCMSRegistry().IsOwnedCodeObject(nil, adapterAddr)
		require.NoError(t, err)
		require.True(t, owned, "adapter code must be owned by MCMS")
	}))

	t.Run("MCMS accept before any transfer is refused", func(t *testing.T) {
		err := cre.AcceptForwarderOwnership{}.VerifyPreconditions(env, cre.AcceptForwarderOwnershipConfig{ChainSelector: selector, MCMS: timelock})
		require.ErrorContains(t, err, "pending owner")
	})

	// ===== 3 + 4. Hand both forwarders to MCMS =====
	require.True(t, t.Run("hand both forwarders to MCMS", func(t *testing.T) {
		env, _ = apply(t, env, cre.TransferForwarderOwnership{}, cre.TransferForwarderOwnershipConfig{ChainSelector: selector})
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.AcceptForwarderOwnership{}, cre.AcceptForwarderOwnershipConfig{ChainSelector: selector, MCMS: timelock})
		execute(t, env, out)

		owner, err := primary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, adapterOwner, owner)
		owner, err = secondary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, adapterOwner, owner)
	}))

	t.Run("direct set_config after the handover is refused", func(t *testing.T) {
		err := cre.SetForwarderConfig{}.VerifyPreconditions(env, cre.SetForwarderConfigConfig{
			ChainSelector: selector, Zone: cre.ZoneA, DON: cre.DON{ID: 1, ConfigVersion: 2, F: 1, NodeIDs: donA},
		})
		require.ErrorContains(t, err, "not the deployer")
	})

	// ===== 5. Config through MCMS =====
	t.Run("set_config through MCMS", func(t *testing.T) {
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.SetForwarderConfig{}, cre.SetForwarderConfigConfig{
			ChainSelector: selector, Zone: cre.ZoneB, MCMS: timelock,
			DON: cre.DON{ID: 2, ConfigVersion: 1, F: 2, NodeIDs: donB},
		})
		execute(t, env, out)
		require.Equal(t, keysB, configOracles(t, chain, secondaryAddr, contracts.PlatformSecondary, 2, 1))
		require.Equal(t, keysA, configOracles(t, chain, primaryAddr, contracts.Platform, 1, 1), "zone-a untouched")
	})

	t.Run("clear_config through MCMS", func(t *testing.T) {
		cfg := cre.ClearForwarderConfigConfig{ChainSelector: selector, Zone: cre.ZoneA, DONID: 1, ConfigVersion: 1, MCMS: timelock}
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.ClearForwarderConfig{}, cfg)
		execute(t, env, out)
		err := cre.ClearForwarderConfig{}.VerifyPreconditions(env, cfg)
		require.ErrorContains(t, err, "has no config")
		require.Equal(t, keysB, configOracles(t, chain, secondaryAddr, contracts.PlatformSecondary, 2, 1), "zone-b untouched")
	})

	t.Run("MCMS hands zone-b back to the deployer", func(t *testing.T) {
		var out cldf.ChangesetOutput
		env, out = apply(t, env, cre.TransferForwarderOwnership{}, cre.TransferForwarderOwnershipConfig{
			ChainSelector: selector, Zones: []cre.Zone{cre.ZoneB}, To: deployer.StringLong(), MCMS: timelock,
		})
		execute(t, env, out)
		env, _ = apply(t, env, cre.AcceptForwarderOwnership{}, cre.AcceptForwarderOwnershipConfig{ChainSelector: selector, Zones: []cre.Zone{cre.ZoneB}})

		owner, err := secondary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, deployer, owner)
		owner, err = primary.Forwarder().GetOwner(nil)
		require.NoError(t, err)
		require.Equal(t, adapterOwner, owner, "zone-a stays with MCMS")
	})
}

// apply runs a changeset (preconditions + apply) and merges its datastore output into env. Its
// proposals are returned unexecuted so tests can observe the state in between.
func apply[C any](t *testing.T, env cldf.Environment, cs cldf.ChangeSetV2[C], cfg C) (cldf.Environment, cldf.ChangesetOutput) {
	t.Helper()
	require.NoError(t, cs.VerifyPreconditions(env, cfg))
	out, err := cs.Apply(env, cfg)
	require.NoError(t, err)
	if out.DataStore != nil {
		ds := datastore.NewMemoryDataStore()
		require.NoError(t, ds.Merge(env.DataStore))
		require.NoError(t, ds.Merge(out.DataStore.Seal()))
		env.DataStore = ds.Seal()
	}
	env.OperationsBundle = operations.NewBundle(env.GetContext, env.Logger, operations.NewMemoryReporter())
	return env, out
}

// execute signs (test MCMS signer) and executes every timelock proposal in out.
func execute(t *testing.T, env cldf.Environment, out cldf.ChangesetOutput) {
	t.Helper()
	require.NotEmpty(t, out.MCMSTimelockProposals, "expected a proposal")
	for _, prop := range out.MCMSTimelockProposals {
		var salt common.Hash
		_, err := rand.Read(salt[:])
		require.NoError(t, err)
		prop.SaltOverride = &salt
		p := cldftesthelpers.SignMCMSTimelockProposal(t, env, &prop, false)
		require.NoError(t, cldftesthelpers.ExecuteMCMSProposalV2(t, env, p))
		if prop.Action == mcmstypes.TimelockActionSchedule {
			require.NoError(t, cldftesthelpers.ExecuteMCMSTimelockProposalV2(t, env, &prop))
		}
	}
}

func refAddress(t *testing.T, env cldf.Environment, typ cldf.ContractType, qualifier string) aptos.AccountAddress {
	t.Helper()
	version := cre.Version1_0_0
	ref, err := env.DataStore.Addresses().Get(datastore.NewAddressRefKey(chain_selectors.APTOS_LOCALNET.Selector, datastore.ContractType(typ), &version, qualifier))
	require.NoError(t, err)
	var addr aptos.AccountAddress
	require.NoError(t, addr.ParseStringRelaxed(ref.Address))
	return addr
}

// withDON adds n nodes with fresh ed25519 Aptos signing keys to the env's test job distributor
// and returns their CSA keys (the node IDs pipelines pass) and the expected oracle keys, sorted.
func withDON(t *testing.T, env *cldf.Environment, selector uint64, name string, n int) ([]string, [][]byte) {
	t.Helper()
	configs := make([]jdtest.NodeConfig, n)
	for i := range configs {
		configs[i] = jdtest.NodeConfig{Name: fmt.Sprintf("%s-node-%d", name, i), ChainSelectors: []uint64{selector}}
	}
	nodes := jdtest.NewNodes(t, configs)
	var ids []string
	var keys [][]byte
	for _, node := range nodes {
		for details, cfg := range node.SelToOCRConfig {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			cfg.OnchainPublicKey = ocrtypes.OnchainPublicKey(pub)
			node.SelToOCRConfig[details] = cfg
			keys = append(keys, pub)
		}
		ids = append(ids, node.CSAKey)
	}
	slices.SortFunc(keys, bytes.Compare)

	// Keep earlier DONs: the job distributor serves every node registered so far.
	all := []deployment.Node{}
	if svc, ok := env.Offchain.(*jdNodes); ok {
		all = append(all, svc.nodes...)
	}
	for _, node := range nodes {
		all = append(all, *node)
	}
	env.Offchain = &jdNodes{JDNodeService: jdtest.NewJDService(all), nodes: all}
	return ids, keys
}

// jdNodes remembers the nodes behind a jdtest service so later DONs can be added to it.
type jdNodes struct {
	*jdtest.JDNodeService
	nodes []deployment.Node
}

// configOracles reads forwarder::get_config(don, version).oracles as raw keys.
func configOracles(t *testing.T, chain cldf_aptos.Chain, fwd aptos.AccountAddress, pkg contracts.Package, donID, version uint32) [][]byte {
	t.Helper()
	c := bind.NewBoundContract(fwd, string(pkg), "forwarder", chain.Client)
	module, fn, typeTags, args, err := c.Encode("get_config", nil, []string{"u32", "u32"}, []any{donID, version})
	require.NoError(t, err)
	res, err := c.Call(nil, module, fn, typeTags, args)
	require.NoError(t, err)
	require.Len(t, res, 1)
	cfg, ok := res[0].(map[string]any)
	require.True(t, ok, "unexpected get_config result %v", res[0])
	raw, ok := cfg["oracles"].([]any)
	require.True(t, ok, "unexpected oracles %v", cfg["oracles"])
	keys := make([][]byte, len(raw))
	for i, o := range raw {
		m, ok := o.(map[string]any)
		require.True(t, ok)
		s, ok := m["bytes"].(string)
		require.True(t, ok)
		keys[i] = common.FromHex(s)
	}
	return keys
}
