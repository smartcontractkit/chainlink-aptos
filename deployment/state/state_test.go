package state

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/types"
)

const (
	testChainSelector uint64 = 743186221051783445
	otherChain        uint64 = 4457093679053095497

	testVersion = "1.0.0"
)

// testVersionValue is the dereferenced form required by cldf.NewTypeAndVersion.
var testVersionValue = *semver.MustParse(testVersion)

func aptosAddr(t *testing.T, s string) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed(s))
	return a
}

func testEnv(t *testing.T, dataStore datastore.DataStore, ab cldf.AddressBook, selectors ...uint64) cldf.Environment {
	t.Helper()
	chains := make(map[uint64]chain.BlockChain, len(selectors))
	for _, selector := range selectors {
		chains[selector] = cldf_aptos.Chain{}
	}
	return cldf.Environment{
		DataStore:         dataStore,
		ExistingAddresses: ab,
		BlockChains:       chain.NewBlockChains(chains),
	}
}

// addRef records one address ref through the same write API shape changesets use:
// every ref carries a version, labels optional.
func addRef(t *testing.T, ds datastore.MutableDataStore, selector uint64, address string, ct cldf.ContractType, labels ...string) datastore.AddressRef {
	t.Helper()
	v := semver.MustParse(testVersion)
	ref := datastore.AddressRef{
		ChainSelector: selector,
		Address:       address,
		Type:          datastore.ContractType(ct),
		Version:       v,
	}
	if len(labels) > 0 {
		ref.Labels = datastore.NewLabelSet(labels...)
	}
	require.NoError(t, ds.Addresses().Add(ref))
	return ref
}

func newDS(t *testing.T) *datastore.MemoryDataStore {
	t.Helper()
	return datastore.NewMemoryDataStore()
}

func newAB(t *testing.T) cldf.AddressBook {
	t.Helper()
	return cldf.NewMemoryAddressBook()
}

func TestLoadOnchainState_FromDataStore(t *testing.T) {
	t.Parallel()

	ds := newDS(t)
	addRef(t, ds, testChainSelector, "0x100", shared.AptosMCMSType)
	addRef(t, ds, testChainSelector, "0x101", shared.AptosCurseMCMSType)
	addRef(t, ds, testChainSelector, "0x102", shared.AptosCCIPType)
	addRef(t, ds, testChainSelector, "0x103", types.LinkToken)
	addRef(t, ds, testChainSelector, "0x104", shared.AptosReceiverType)
	addRef(t, ds, testChainSelector, "0x105", shared.AptosManagedTokenType, "LINK")
	addRef(t, ds, testChainSelector, "0x106", shared.AptosRegulatedTokenType, "FOO")
	addRef(t, ds, testChainSelector, "0x107", shared.AptosManagedTokenPoolType, "0x1")
	addRef(t, ds, testChainSelector, "0x108", shared.AptosRegulatedTokenPoolType, "0x2")
	addRef(t, ds, testChainSelector, "0x109", shared.BurnMintTokenPool, "0x3")
	addRef(t, ds, testChainSelector, "0x10a", shared.LockReleaseTokenPool, "0x4")
	// Noise that must not leak into the state: an unknown type, and a ref of another chain.
	addRef(t, ds, testChainSelector, "0x10b", "SomeUnknownType")
	addRef(t, ds, otherChain, "0x10c", shared.AptosCCIPType)

	got, err := LoadOnchainState(testEnv(t, ds.Seal(), newAB(t), testChainSelector, otherChain))
	require.NoError(t, err)

	state, ok := got[testChainSelector]
	require.True(t, ok, "state for test chain missing")
	assert.Equal(t, aptosAddr(t, "0x100"), state.MCMSAddress)
	assert.Equal(t, aptosAddr(t, "0x101"), state.CurseMCMSAddress)
	assert.Equal(t, aptosAddr(t, "0x102"), state.CCIPAddress)
	assert.Equal(t, aptosAddr(t, "0x103"), state.LinkTokenAddress)
	assert.Equal(t, aptosAddr(t, "0x104"), state.ReceiverAddress)
	assert.Equal(t, map[shared.TokenSymbol]aptos.AccountAddress{
		"LINK": aptosAddr(t, "0x105"),
		"FOO":  aptosAddr(t, "0x106"),
	}, state.ManagedTokens)
	assert.Equal(t, map[aptos.AccountAddress]aptos.AccountAddress{
		aptosAddr(t, "0x1"): aptosAddr(t, "0x107"),
	}, state.AptosManagedTokenPools)
	assert.Equal(t, map[aptos.AccountAddress]aptos.AccountAddress{
		aptosAddr(t, "0x2"): aptosAddr(t, "0x108"),
	}, state.RegulatedTokenPools)
	assert.Equal(t, map[aptos.AccountAddress]aptos.AccountAddress{
		aptosAddr(t, "0x3"): aptosAddr(t, "0x109"),
	}, state.BurnMintTokenPools)
	assert.Equal(t, map[aptos.AccountAddress]aptos.AccountAddress{
		aptosAddr(t, "0x4"): aptosAddr(t, "0x10a"),
	}, state.LockReleaseTokenPools)

	otherState, ok := got[otherChain]
	require.True(t, ok, "state for other chain missing")
	assert.Equal(t, aptosAddr(t, "0x10c"), otherState.CCIPAddress)
	assert.Zero(t, otherState.MCMSAddress)
}

func TestLoadOnchainState_SkipsSupersededRefs(t *testing.T) {
	t.Parallel()

	ds := newDS(t)
	addRef(t, ds, testChainSelector, "0x200", shared.AptosCCIPType)
	addRef(t, ds, testChainSelector, "0x201", shared.AptosMCMSType, supersededLabel)

	// The address book is never consulted; the AB entry must not leak into the state.
	ab := newAB(t)
	require.NoError(t, ab.Save(testChainSelector, "0x203", cldf.NewTypeAndVersion(shared.AptosCCIPType, testVersionValue)))

	got, err := LoadOnchainState(testEnv(t, ds.Seal(), ab, testChainSelector))
	require.NoError(t, err)

	state := got[testChainSelector]
	assert.Equal(t, aptosAddr(t, "0x200"), state.CCIPAddress, "live datastore ref must win over the address book")
	assert.Zero(t, state.MCMSAddress, "superseded ref must be skipped")
}

func TestLoadOnchainState_RejectsVersionlessRefs(t *testing.T) {
	t.Parallel()

	ds := newDS(t)
	addRef(t, ds, testChainSelector, "0x202", shared.AptosCCIPType)
	// A versionless ref cannot go through Add (the store requires a version); inject it
	// the way a file-backed store would load one.
	ds.AddressRefStore.Records = append(ds.AddressRefStore.Records, datastore.AddressRef{
		ChainSelector: testChainSelector,
		Address:       "0x203",
		Type:          datastore.ContractType(types.LinkToken),
	})

	_, err := LoadOnchainState(testEnv(t, ds.Seal(), newAB(t), testChainSelector))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x203")
	assert.Contains(t, err.Error(), "has no version")
}

func TestLoadOnchainState_NoDatastoreRefsYieldsEmptyState(t *testing.T) {
	t.Parallel()

	// The address book is never consulted: whatever it holds must not leak into the state.
	ab := newAB(t)
	require.NoError(t, ab.Save(testChainSelector, "0x300", cldf.NewTypeAndVersion(shared.AptosCCIPType, testVersionValue)))
	require.NoError(t, ab.Save(testChainSelector, "0x301", cldf.NewTypeAndVersion(types.LinkToken, testVersionValue)))

	t.Run("nil datastore", func(t *testing.T) {
		t.Parallel()
		got, err := LoadOnchainState(testEnv(t, nil, ab, testChainSelector))
		require.NoError(t, err)
		assert.Zero(t, got[testChainSelector].CCIPAddress)
		assert.Zero(t, got[testChainSelector].LinkTokenAddress)
	})

	t.Run("empty datastore", func(t *testing.T) {
		t.Parallel()
		got, err := LoadOnchainState(testEnv(t, newDS(t).Seal(), ab, testChainSelector))
		require.NoError(t, err)
		assert.Zero(t, got[testChainSelector].CCIPAddress)
		assert.Zero(t, got[testChainSelector].LinkTokenAddress)
	})

	t.Run("datastore holds refs only for another chain", func(t *testing.T) {
		t.Parallel()
		ds := newDS(t)
		addRef(t, ds, otherChain, "0x302", shared.AptosCCIPType)
		got, err := LoadOnchainState(testEnv(t, ds.Seal(), ab, testChainSelector, otherChain))
		require.NoError(t, err)
		assert.Zero(t, got[testChainSelector].CCIPAddress)
		assert.Zero(t, got[testChainSelector].LinkTokenAddress)
		otherState, ok := got[otherChain]
		require.True(t, ok)
		assert.Equal(t, aptosAddr(t, "0x302"), otherState.CCIPAddress)
	})
}

func TestLoadOnchainState_AddressBookIsIgnored(t *testing.T) {
	t.Parallel()

	ds := newDS(t)
	addRef(t, ds, testChainSelector, "0x400", shared.AptosCCIPType)

	ab := newAB(t)
	require.NoError(t, ab.Save(testChainSelector, "0x401", cldf.NewTypeAndVersion(shared.AptosCCIPType, testVersionValue)))

	got, err := LoadOnchainState(testEnv(t, ds.Seal(), ab, testChainSelector))
	require.NoError(t, err)
	assert.Equal(t, aptosAddr(t, "0x400"), got[testChainSelector].CCIPAddress)
}

func TestLoadOnchainState_AllDatastoreRefsSupersededYieldsEmptyState(t *testing.T) {
	t.Parallel()

	ds := newDS(t)
	addRef(t, ds, testChainSelector, "0x500", shared.AptosCCIPType, supersededLabel)

	ab := newAB(t)
	require.NoError(t, ab.Save(testChainSelector, "0x501", cldf.NewTypeAndVersion(shared.AptosCCIPType, testVersionValue)))

	got, err := LoadOnchainState(testEnv(t, ds.Seal(), ab, testChainSelector))
	require.NoError(t, err)
	assert.Zero(t, got[testChainSelector].CCIPAddress)
}

func TestLoadCCIPOnChainStateUsingDataStore(t *testing.T) {
	t.Parallel()

	t.Run("loads refs of the chain", func(t *testing.T) {
		t.Parallel()
		ds := newDS(t)
		addRef(t, ds, testChainSelector, "0x600", shared.AptosCCIPType)
		addRef(t, ds, testChainSelector, "0x601", shared.AptosManagedTokenType, "LINK")
		addRef(t, ds, otherChain, "0x602", shared.AptosCCIPType)

		state, err := LoadCCIPOnChainStateUsingDataStore(ds.Seal(), testChainSelector, nil)
		require.NoError(t, err)
		assert.Equal(t, aptosAddr(t, "0x600"), state.CCIPAddress)
		assert.Equal(t, map[shared.TokenSymbol]aptos.AccountAddress{
			"LINK": aptosAddr(t, "0x601"),
		}, state.ManagedTokens)
	})

	t.Run("no refs for the chain yields an empty state", func(t *testing.T) {
		t.Parallel()
		state, err := LoadCCIPOnChainStateUsingDataStore(newDS(t).Seal(), testChainSelector, nil)
		require.NoError(t, err)
		assert.Zero(t, state.CCIPAddress)
		assert.Zero(t, state.MCMSAddress)
		assert.Zero(t, state.LinkTokenAddress)
		assert.Empty(t, state.ManagedTokens)
	})

	t.Run("superseded refs yield an empty state", func(t *testing.T) {
		t.Parallel()
		ds := newDS(t)
		addRef(t, ds, testChainSelector, "0x603", shared.AptosCCIPType, supersededLabel)

		state, err := LoadCCIPOnChainStateUsingDataStore(ds.Seal(), testChainSelector, nil)
		require.NoError(t, err)
		assert.Zero(t, state.CCIPAddress)
	})
}
