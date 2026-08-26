package ccip

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	aptosstate "github.com/smartcontractkit/chainlink-aptos/deployment/state"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
)

func mustAddress(t *testing.T, s string) aptos.AccountAddress {
	t.Helper()
	var address aptos.AccountAddress
	require.NoError(t, address.ParseStringRelaxed(s))
	return address
}

// The token symbol is the datastore qualifier for every ref AddTokenPool records, so a symbol
// that disagrees with the token already recorded on that chain must be rejected before deploy.
// Both cases resolve from loaded state, so no RPC client is needed.
func TestVerifyTokenSymbol_AgainstRecordedState(t *testing.T) {
	const chainSelector uint64 = 4457093679053095497
	codeObject := mustAddress(t, "0x1111111111111111111111111111111111111111111111111111111111111111")
	tokenAddress := mustAddress(t, "0x2222222222222222222222222222222222222222222222222222222222222222")

	state := stateview.CCIPOnChainState{
		AptosChains: map[uint64]aptosstate.CCIPChainState{
			chainSelector: {
				ManagedTokens: map[shared.TokenSymbol]aptos.AccountAddress{
					shared.LinkSymbol: codeObject,
				},
			},
		},
	}
	cfg := config.AddTokenPoolConfig{
		ChainSelector:       chainSelector,
		TokenCodeObjAddress: codeObject,
		TokenAddress:        tokenAddress,
		TokenParams:         config.TokenParams{Symbol: shared.LinkSymbol},
	}

	require.NoError(t, verifyTokenSymbol(cldf.Environment{}, cfg, state))

	cfg.TokenParams.Symbol = "USDC"
	err := verifyTokenSymbol(cldf.Environment{}, cfg, state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `does not match the recorded symbol "LINK"`)
}

// The plan must mirror Apply's conditionals: a caller-supplied address means that contract is
// not deployed on this run, so its key is not claimed and must not be reported as a conflict.
func TestPlannedTokenPoolRefs_MirrorsApplyConditionals(t *testing.T) {
	const chainSelector uint64 = 4457093679053095497
	existing := mustAddress(t, "0x1111111111111111111111111111111111111111111111111111111111111111")

	cfg := config.AddTokenPoolConfig{
		ChainSelector: chainSelector,
		PoolType:      shared.AptosManagedTokenPoolType,
		TokenParams:   config.TokenParams{Symbol: shared.LinkSymbol},
	}

	// Fresh token and pool: token object, token metadata and pool.
	assert.Len(t, plannedTokenPoolRefs(cfg), 3)

	// Pre-existing token, new pool: only the pool.
	cfg.TokenCodeObjAddress = existing
	refs := plannedTokenPoolRefs(cfg)
	require.Len(t, refs, 1)
	assert.Equal(t, shared.AptosManagedTokenPoolType, refs[0].Type)
	assert.Equal(t, string(shared.LinkSymbol), refs[0].Qualifier)
	assert.True(t, refs[0].MultiInstance)

	// Pre-existing token and pool: nothing is recorded, so nothing is claimed.
	cfg.TokenPoolAddress = existing
	assert.Empty(t, plannedTokenPoolRefs(cfg))
}

// Regression: the fresh token+pool path (both addresses zero) used to return from
// VerifyPreconditions before the datastore preflight ran. That path records the most refs,
// so it is exactly where an occupied key must stop the run before anything is deployed.
func TestVerifyPreconditions_FreshDeployChecksDatastoreConflicts(t *testing.T) {
	const chainSelector uint64 = 4457093679053095497
	version := Version1_6_0
	existing := datastore.NewMemoryDataStore()
	require.NoError(t, existing.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSelector,
		Address:       "0x3333333333333333333333333333333333333333333333333333333333333333",
		Type:          datastore.ContractType(shared.AptosManagedTokenType),
		Version:       &version,
		Qualifier:     "BnM",
	}))
	env := cldf.Environment{
		DataStore:   existing.Seal(),
		BlockChains: cldf_chain.NewBlockChains(map[uint64]cldf_chain.BlockChain{}),
	}
	cfg := config.AddTokenPoolConfig{
		ChainSelector: chainSelector,
		PoolType:      shared.AptosManagedTokenPoolType,
		MCMSConfig:    &cldfproposalutils.TimelockConfig{},
		TokenParams:   config.TokenParams{Name: "BnMTest", Symbol: "BnM", Decimals: 8},
	}

	err := AddTokenPool{}.VerifyPreconditions(env, cfg)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "datastore conflict")
}

// With ReplaceExisting set, an intentional redeploy may take the occupied key.
func TestVerifyPreconditions_ReplaceExistingAllowsRedeploy(t *testing.T) {
	const chainSelector uint64 = 4457093679053095497
	version := Version1_6_0
	existing := datastore.NewMemoryDataStore()
	require.NoError(t, existing.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainSelector,
		Address:       "0x3333333333333333333333333333333333333333333333333333333333333333",
		Type:          datastore.ContractType(shared.AptosManagedTokenType),
		Version:       &version,
		Qualifier:     "BnM",
	}))
	env := cldf.Environment{
		DataStore:   existing.Seal(),
		BlockChains: cldf_chain.NewBlockChains(map[uint64]cldf_chain.BlockChain{}),
	}
	cfg := config.AddTokenPoolConfig{
		ChainSelector:   chainSelector,
		PoolType:        shared.AptosManagedTokenPoolType,
		MCMSConfig:      &cldfproposalutils.TimelockConfig{},
		TokenParams:     config.TokenParams{Name: "BnMTest", Symbol: "BnM", Decimals: 8},
		ReplaceExisting: true,
	}

	err := AddTokenPool{}.VerifyPreconditions(env, cfg)

	// Other precondition failures (unsupported chain, CCIP not deployed) are expected with an
	// empty environment; the datastore conflict must not be among them.
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "datastore conflict")
}
