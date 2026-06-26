package ccip

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/runtime"

	cldflogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types/ccipocr3"
	cldftesthelpers "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils/testhelpers"

	"github.com/smartcontractkit/chainlink-ccip/chainconfig"
	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_0/rmn_home"
	capabilities_registry "github.com/smartcontractkit/chainlink-evm/gethwrappers/keystone/generated/capabilities_registry_1_1_0"

	"github.com/smartcontractkit/chainlink/deployment"
	jdtest "github.com/smartcontractkit/chainlink/deployment/environment/test"
	commonchangeset "github.com/smartcontractkit/chainlink/deployment/common/changeset"
	"github.com/smartcontractkit/chainlink/deployment/common/proposalutils"
	commontypes "github.com/smartcontractkit/chainlink/deployment/common/types"
	"github.com/smartcontractkit/chainlink/deployment/ccip/changeset/v1_6"
	ccipcaptypes "github.com/smartcontractkit/chainlink/v2/core/capabilities/ccip/types"

	aptosfeequoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	aptoscs "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	aptosv1_6 "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/v1_6"
	"github.com/smartcontractkit/chainlink-aptos/deployment/types"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"
	devenv "github.com/smartcontractkit/chainlink-aptos/integration-tests/environment"

	ocrtypes "github.com/smartcontractkit/libocr/offchainreporting2/types"
	ocr3types "github.com/smartcontractkit/libocr/offchainreporting2plus/types"
)

const (
	mockMCMSAddress = "0x3f20aa841a0eb5c038775bdb868924770df1ce377cc0013b3ba4ac9fd69a4f90"
	mockAddress     = "0x13a9f1a109368730f2e355d831ba8fbf5942fb82321863d55de54cb4ebe5d18f"

	sepChainSelector     = 11155111
	sepMockOnRampAddress = "0x0BF3dE8c5D3e8A2B34D2BEeB17ABfCeBaf363A59"
)

func getTestAddressBook(t *testing.T, addrByChain map[uint64]map[string]cldf.TypeAndVersion) cldf.AddressBook {
	ab := cldf.NewMemoryAddressBook()
	for chain, addrTypeAndVersion := range addrByChain {
		for addr, typeAndVersion := range addrTypeAndVersion {
			err := ab.Save(chain, addr, typeAndVersion)
			require.NoError(t, err)
		}
	}
	return ab
}

func MustParseAddress(t *testing.T, addr string) aptos.AccountAddress {
	t.Helper()
	var address aptos.AccountAddress
	err := address.ParseStringRelaxed(addr)
	assert.NoError(t, err)
	return address
}

func GetMockChainContractParams(t *testing.T, chainSelector uint64) config.ChainContractParams {
	mockParsedAddress := MustParseAddress(t, mockAddress)
	mockParsedLinkAddress := MustParseAddress(t, shared.AptosAPTAddress)

	return config.ChainContractParams{
		FeeQuoterParams: config.FeeQuoterParams{
			MaxFeeJuelsPerMsg:            big.NewInt(1000000),
			TokenPriceStalenessThreshold: 1000000,
			FeeTokens:                    []aptos.AccountAddress{mockParsedLinkAddress},
			PremiumMultiplierWeiPerEthByFeeToken: map[shared.TokenSymbol]uint64{
				shared.APTSymbol:  1_000_000_000_000_000_000,
				shared.LinkSymbol: 900_000_000_000_000_000,
			},
		},
		OffRampParams: config.OffRampParams{
			ChainSelector:                    chainSelector,
			PermissionlessExecutionThreshold: uint32(60 * 60 * 8),
			IsRMNVerificationDisabled:        []bool{false},
			SourceChainSelectors:             []uint64{sepChainSelector},
			SourceChainIsEnabled:             []bool{true},
			SourceChainsOnRamp:               [][]byte{common.HexToAddress(sepMockOnRampAddress).Bytes()},
		},
		OnRampParams: config.OnRampParams{
			ChainSelector:  chainSelector,
			AllowlistAdmin: mockParsedAddress,
			FeeAggregator:  mockParsedAddress,
		},
	}
}

func getMockMCMSConfig(t *testing.T) types.MCMSWithTimelockConfigV2 {
	mcmsConfig := cldftesthelpers.SingleGroupMCMS(t)
	return types.MCMSWithTimelockConfigV2{
		Canceller:        mcmsConfig,
		Proposer:         mcmsConfig,
		Bypasser:         mcmsConfig,
		TimelockMinDelay: big.NewInt(1),
	}
}

// newAptosOnlyEnvWithCCIP spins up a single Aptos container via runtime.New, deploys CCIP on it,
// and returns the resulting cldf.Environment. This is the lightweight alternative to
// testhelpers.NewMemoryEnvironment for tests that don't need EVM chains or Chainlink nodes.
func newAptosOnlyEnvWithCCIP(t *testing.T) (cldf.Environment, uint64) {
	t.Helper()

	selector := chain_selectors.APTOS_LOCALNET.Selector
	rt, err := runtime.New(t.Context(), runtime.WithEnvOpts(
		environment.WithAptosContainer(t, []uint64{selector}),
		environment.WithLogger(cldflogger.Test(t)),
	))
	require.NoError(t, err)

	ccipConfig := config.DeployAptosChainConfig{
		ContractParamsPerChain: map[uint64]config.ChainContractParams{
			selector: GetMockChainContractParams(t, selector),
		},
		MCMSDeployConfigPerChain: map[uint64]types.MCMSWithTimelockConfigV2{
			selector: getMockMCMSConfig(t),
		},
		MCMSTimelockConfigPerChain: map[uint64]cldfproposalutils.TimelockConfig{
			selector: {
				MinDelay:     time.Second,
				MCMSAction:   mcmstypes.TimelockActionSchedule,
				OverrideRoot: false,
			},
		},
	}

	err = rt.Exec(
		runtime.ChangesetTask(aptoscs.DeployAptosChain{}, ccipConfig),
		runtime.SignAndExecuteProposalsTask([]*ecdsa.PrivateKey{cldftesthelpers.TestXXXMCMSSigner}),
	)
	require.NoError(t, err)

	return rt.Environment(), selector
}

// newAptosEVMEnvWithCCIP spins up Aptos plus simulated EVM chains and deploys CCIP on Aptos.
func newAptosEVMEnvWithCCIP(t *testing.T, evmChains int) (cldf.Environment, uint64) {
	t.Helper()

	env, err := devenv.NewTestEnvironmentBuilder(cldflogger.Test(t)).
		WithAptos().
		WithEVMN(evmChains).
		Build(t)
	require.NoError(t, err)

	selector := devenv.AptosSelector(env)
	ccipConfig := config.DeployAptosChainConfig{
		ContractParamsPerChain: map[uint64]config.ChainContractParams{
			selector: GetMockChainContractParams(t, selector),
		},
		MCMSDeployConfigPerChain: map[uint64]types.MCMSWithTimelockConfigV2{
			selector: getMockMCMSConfig(t),
		},
		MCMSTimelockConfigPerChain: map[uint64]cldfproposalutils.TimelockConfig{
			selector: {
				MinDelay:     time.Second,
				MCMSAction:   mcmstypes.TimelockActionSchedule,
				OverrideRoot: false,
			},
		},
	}

	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(aptoscs.DeployAptosChain{}, ccipConfig),
	})
	require.NoError(t, err)

	return env, selector
}

const testNodeOperator = "TestNodeOperator"

// patchJDTestOCRNodeKeys fixes jdtest OCR node keys for Aptos integration tests.
// jdtest seeds keys from peer IDs, which are not valid Ed25519 public keys and are
// rejected by Aptos OCR3 on-chain validation. Aptos transmit accounts must also be
// 32-byte public key hex strings, not EVM 0x addresses (upstream fix: chainlink#22165).
func patchJDTestOCRNodeKeys(t *testing.T, nodes []*deployment.Node) {
	t.Helper()

	for _, n := range nodes {
		onchainPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		offchainPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		configPub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		for details, cfg := range n.SelToOCRConfig {
			cfg.OnchainPublicKey = ocrtypes.OnchainPublicKey(onchainPub)
			cfg.OffchainPublicKey = ocrtypes.OffchainPublicKey(offchainPub)
			cfg.ConfigEncryptionPublicKey = ocr3types.ConfigEncryptionPublicKey(configPub)

			family, err := chain_selectors.GetSelectorFamily(details.ChainSelector)
			if err == nil && family == chain_selectors.FamilyAptos {
				cfg.TransmitAccount = ocrtypes.Account(hex.EncodeToString(onchainPub))
			}
			n.SelToOCRConfig[details] = cfg
		}
	}
}

// newAptosEVMEnvWithOCR3HomeChain deploys Aptos CCIP, wires a mock job distributor with
// EVM home-chain + Aptos OCR node configs, and runs the v1_6 home-chain setup steps
// required before SetOCR3Config can target Aptos offramps.
func newAptosEVMEnvWithOCR3HomeChain(t *testing.T) (cldf.Environment, uint64, uint64) {
	t.Helper()

	env, aptosSelector := newAptosEVMEnvWithCCIP(t, 1)

	evmSelectors := env.BlockChains.ListChainSelectors(cldf_chain.WithFamily(chain_selectors.FamilyEVM))
	require.Len(t, evmSelectors, 1)
	homeChainSel := evmSelectors[0]

	nodeConfigs := make([]jdtest.NodeConfig, 4)
	for i := range nodeConfigs {
		nodeConfigs[i] = jdtest.NodeConfig{
			Name:           fmt.Sprintf("node-%d", i+1),
			ChainSelectors: []uint64{homeChainSel, aptosSelector},
		}
	}
	nodePtrs := jdtest.NewNodes(t, nodeConfigs)
	patchJDTestOCRNodeKeys(t, nodePtrs)
	deploymentNodes := make([]deployment.Node, len(nodePtrs))
	nodeIDs := make([]string, len(nodePtrs))
	testP2PIDs := make([][32]byte, len(nodePtrs))
	for i, n := range nodePtrs {
		deploymentNodes[i] = *n
		nodeIDs[i] = n.NodeID
		testP2PIDs[i] = n.PeerID
	}

	env.NodeIDs = nodeIDs
	env.Offchain = jdtest.NewJDService(deploymentNodes)

	var err error
	env, _, err = testutil.ApplyChangesets(t, env, []testutil.ConfiguredChangeSet{
		testutil.Configure(cldf.CreateLegacyChangeSet(v1_6.DeployHomeChainChangeset), v1_6.DeployHomeChainConfig{
			HomeChainSel: homeChainSel,
			RMNStaticConfig: rmn_home.RMNHomeStaticConfig{
				Nodes:          []rmn_home.RMNHomeNode{},
				OffchainConfig: []byte{},
			},
			RMNDynamicConfig: rmn_home.RMNHomeDynamicConfig{
				SourceChains:   []rmn_home.RMNHomeSourceChain{},
				OffchainConfig: []byte{},
			},
			NodeOperators: []capabilities_registry.CapabilitiesRegistryNodeOperator{
				{
					Admin: env.BlockChains.EVMChains()[homeChainSel].DeployerKey.From,
					Name:  testNodeOperator,
				},
			},
			NodeP2PIDsPerNodeOpAdmin: map[string][][32]byte{
				testNodeOperator: testP2PIDs,
			},
		}),
		testutil.Configure(cldf.CreateLegacyChangeSet(commonchangeset.DeployMCMSWithTimelockV2), map[uint64]commontypes.MCMSWithTimelockConfigV2{
			homeChainSel: {
				Proposer:         proposalutils.SingleGroupMCMSV2(t),
				Bypasser:         proposalutils.SingleGroupMCMSV2(t),
				Canceller:        proposalutils.SingleGroupMCMSV2(t),
				TimelockMinDelay: big.NewInt(0),
			},
		}),
		testutil.Configure(cldf.CreateLegacyChangeSet(v1_6.UpdateChainConfigChangeset), v1_6.UpdateChainConfigConfig{
			HomeChainSelector: homeChainSel,
			RemoteChainAdds: map[uint64]v1_6.ChainConfig{
				aptosSelector: {
					Readers: testP2PIDs,
					FChain:  1,
					EncodableChainConfig: chainconfig.ChainConfig{
						GasPriceDeviationPPB:    ccipocr3.NewBigIntFromInt64(1000),
						DAGasPriceDeviationPPB:  ccipocr3.NewBigIntFromInt64(1000),
						OptimisticConfirmations: 1,
					},
				},
			},
		}),
		testutil.Configure(cldf.CreateLegacyChangeSet(v1_6.AddDonAndSetCandidateChangeset), v1_6.AddDonAndSetCandidateChangesetConfig{
			SetCandidateConfigBase: v1_6.SetCandidateConfigBase{
				HomeChainSelector: homeChainSel,
				FeedChainSelector: homeChainSel,
			},
			PluginInfo: v1_6.SetCandidatePluginInfo{
				OCRConfigPerRemoteChainSelector: map[uint64]v1_6.CCIPOCRParams{
					aptosSelector: v1_6.OcrParamsForTest,
				},
				PluginType: ccipcaptypes.PluginTypeCCIPCommit,
			},
		}),
		testutil.Configure(cldf.CreateLegacyChangeSet(v1_6.SetCandidateChangeset), v1_6.SetCandidateChangesetConfig{
			SetCandidateConfigBase: v1_6.SetCandidateConfigBase{
				HomeChainSelector: homeChainSel,
				FeedChainSelector: homeChainSel,
			},
			PluginInfo: []v1_6.SetCandidatePluginInfo{
				{
					OCRConfigPerRemoteChainSelector: map[uint64]v1_6.CCIPOCRParams{
						aptosSelector: v1_6.OcrParamsForTest,
					},
					PluginType: ccipcaptypes.PluginTypeCCIPExec,
				},
			},
		}),
		testutil.Configure(cldf.CreateLegacyChangeSet(v1_6.PromoteCandidateChangeset), v1_6.PromoteCandidateChangesetConfig{
			HomeChainSelector: homeChainSel,
			PluginInfo: []v1_6.PromoteCandidatePluginInfo{
				{
					RemoteChainSelectors: []uint64{aptosSelector},
					PluginType:           ccipcaptypes.PluginTypeCCIPCommit,
				},
				{
					RemoteChainSelectors: []uint64{aptosSelector},
					PluginType:           ccipcaptypes.PluginTypeCCIPExec,
				},
			},
		}),
	})
	require.NoError(t, err)

	return env, aptosSelector, homeChainSel
}

func aptosTestDestFeeQuoterConfig(t *testing.T) aptosfeequoter.DestChainConfig {
	t.Helper()
	return aptosv1_6.ToAptosFeeQuoterDestChainConfig(aptosv1_6.DefaultAptosLaneFeeQuoterDestChainConfig())
}
