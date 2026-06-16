package ccip

import (
	"crypto/ecdsa"
	"encoding/hex"
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
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/environment"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/test/runtime"

	cldflogger "github.com/smartcontractkit/chainlink-common/pkg/logger"
	cldftesthelpers "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils/testhelpers"

	aptosfeequoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	aptoscs "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/v1_6"
	"github.com/smartcontractkit/chainlink-aptos/deployment/types"
	devenv "github.com/smartcontractkit/chainlink-aptos/integration-tests/env"
	"github.com/smartcontractkit/chainlink-aptos/integration-tests/deployment/testutil"
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

func aptosTestDestFeeQuoterConfig(t *testing.T) aptosfeequoter.DestChainConfig {
	t.Helper()
	return aptosfeequoter.DestChainConfig{
		IsEnabled:                         true,
		MaxNumberOfTokensPerMsg:           11,
		MaxDataBytes:                      40_000,
		MaxPerMsgGasLimit:                 4_000_000,
		DestGasOverhead:                   300_000,
		DefaultTokenFeeUsdCents:           30,
		DestGasPerPayloadByteBase:         16,
		DestGasPerPayloadByteHigh:         40,
		DestGasPerPayloadByteThreshold:    3000,
		DestDataAvailabilityOverheadGas:   700,
		DestGasPerDataAvailabilityByte:    17,
		DestDataAvailabilityMultiplierBps: 2,
		DefaultTokenDestGasOverhead:       100_000,
		DefaultTxGasLimit:                 100_000,
		GasMultiplierWeiPerEth:            1e7,
		NetworkFeeUsdCents:                20,
		ChainFamilySelector:               hexMustDecode(t, v1_6.AptosFamilySelector),
		EnforceOutOfOrder:                 false,
		GasPriceStalenessThreshold:        2,
	}
}

func hexMustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
