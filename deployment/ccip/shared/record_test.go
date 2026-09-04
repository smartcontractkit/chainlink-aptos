package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

func newStores() (cldf.AddressBook, datastore.MutableDataStore) {
	return cldf.NewMemoryAddressBook(), datastore.NewMemoryDataStore()
}

func fetchRefs(t *testing.T, ds datastore.MutableDataStore) []datastore.AddressRef {
	t.Helper()
	refs, err := ds.Addresses().Fetch()
	require.NoError(t, err)
	return refs
}

// Both registries carry identical metadata from one TypeAndVersion, labels included: the
// state loader reads the labels to reconstruct the TypeAndVersion without RPC.
func TestRecordAddress_WritesBothStoresIdentically(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)
	tv.AddLabel(poolB) // pools carry the token address as a label

	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, tv, "LINK"))

	bookEntry, err := ab.AddressesForChain(chainA)
	require.NoError(t, err)
	require.Equal(t, tv, bookEntry[poolA])

	refs := fetchRefs(t, ds)
	require.Len(t, refs, 1)
	ref := refs[0]
	assert.Equal(t, chainA, ref.ChainSelector)
	assert.Equal(t, poolA, ref.Address)
	assert.Equal(t, datastore.ContractType(AptosManagedTokenPoolType), ref.Type)
	assert.Equal(t, version1_6_0, *ref.Version)
	assert.Equal(t, "LINK", ref.Qualifier)
	assert.Equal(t, []string{poolB}, ref.Labels.List())
}

func TestRecordAddress_QualifierNeverDerivedFromAddress(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)

	err := RecordAddress(ab, ds, chainA, poolA, tv, poolA+"-"+string(AptosManagedTokenPoolType))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "contains the address being written")
	assert.Empty(t, fetchRefs(t, ds))
}

func TestRecordAddress_EmptyAddressRejected(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosCCIPType, version1_6_0)

	err := RecordAddress(ab, ds, chainA, "", tv, ChainSingletonQualifier)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "address is empty")
	assert.Empty(t, fetchRefs(t, ds))
}

// Two pools of the same type on one chain are distinguished only by their qualifier, since
// the datastore key is (chain, type, version, qualifier) and excludes the address. A
// collision must fail the changeset with neither store touched silently keeping one ref
// would lose the other address.
func TestRecordAddress_SameKeyDifferentAddressFailsAndTouchesNothing(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)
	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, tv, "LINK"))

	err := RecordAddress(ab, ds, chainA, poolB, tv, "LINK")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "two contracts cannot share one datastore key")
	// The failed write touched nothing: the address book holds only the first pool...
	bookEntry, bookErr := ab.AddressesForChain(chainA)
	require.NoError(t, bookErr)
	assert.NotContains(t, bookEntry, poolB)
	// ...and the datastore still holds exactly the first ref.
	refs := fetchRefs(t, ds)
	require.Len(t, refs, 1)
	assert.Equal(t, poolA, refs[0].Address)
}

// AddressBookMap.Save rejects repeats outright, so the helper checks first: a repeat with a
// different type/version is an error raised before the datastore is written.
func TestRecordAddress_SameAddressDifferentTypeFailsAndLeavesDataStoreUntouched(t *testing.T) {
	ab, ds := newStores()
	poolTV := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)
	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, poolTV, "LINK"))

	tokenTV := cldf.NewTypeAndVersion(AptosManagedTokenType, version1_6_0)
	err := RecordAddress(ab, ds, chainA, poolA, tokenTV, "USDC")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "address book already holds")
	require.Len(t, fetchRefs(t, ds), 1)
}

// Re-recording the same contract — same key, same address — is a true no-op.
func TestRecordAddress_ReRecordingIsANoOp(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)

	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, tv, "LINK"))
	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, tv, "LINK"))

	bookEntry, err := ab.AddressesForChain(chainA)
	require.NoError(t, err)
	assert.Len(t, bookEntry, 1)
	assert.Len(t, fetchRefs(t, ds), 1)
}

func TestRecordAddress_RestoresMissingAddressBookEntry(t *testing.T) {
	ab := cldf.NewMemoryAddressBook()
	ds := datastore.NewMemoryDataStore()
	tv := cldf.NewTypeAndVersion(AptosCCIPType, version1_6_0)
	version := tv.Version

	require.NoError(t, ds.Addresses().Add(datastore.AddressRef{
		ChainSelector: chainA,
		Address:       ccipAd,
		Type:          datastore.ContractType(tv.Type),
		Version:       &version,
	}))
	require.NoError(t, RecordAddress(ab, ds, chainA, ccipAd, tv, ChainSingletonQualifier))

	addresses, err := ab.AddressesForChain(chainA)
	require.NoError(t, err)
	assert.Equal(t, tv, addresses[ccipAd])
}

// A chain singleton needs no qualifier: the type alone keys the instance.
func TestRecordAddress_ChainSingletonTakesEmptyQualifier(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosCCIPType, version1_6_0)

	require.NoError(t, RecordAddress(ab, ds, chainA, ccipAd, tv, ChainSingletonQualifier))

	refs := fetchRefs(t, ds)
	require.Len(t, refs, 1)
	assert.Equal(t, "", refs[0].Qualifier)
}

func TestRecordAddress_NilAddressBookStillWritesDataStore(t *testing.T) {
	ds := datastore.NewMemoryDataStore()
	tv := cldf.NewTypeAndVersion(AptosCCIPType, version1_6_0)

	require.NoError(t, RecordAddress(nil, ds, chainA, ccipAd, tv, ChainSingletonQualifier))

	refs := fetchRefs(t, ds)
	require.Len(t, refs, 1)
	assert.Equal(t, ccipAd, refs[0].Address)
}

// Aptos object addresses are derived from deployer plus seed, so the same address can appear
// on several chains with different roles; the chain selector is part of the key.
func TestRecordAddress_QualifiersAreScopedPerChain(t *testing.T) {
	ab, ds := newStores()
	tv := cldf.NewTypeAndVersion(AptosManagedTokenPoolType, version1_6_0)

	require.NoError(t, RecordAddress(ab, ds, chainA, poolA, tv, "LINK"))
	require.NoError(t, RecordAddress(ab, ds, chainB, poolA, tv, "USDC"))

	byChain := make(map[uint64]string, 2)
	for _, ref := range fetchRefs(t, ds) {
		byChain[ref.ChainSelector] = ref.Qualifier
	}
	assert.Equal(t, map[uint64]string{chainA: "LINK", chainB: "USDC"}, byChain)
}

func TestTokenQualifier_NormalizesDisplayNameSpacing(t *testing.T) {
	assert.Equal(t, "CCIP-BnM", TokenQualifier("CCIP BnM"))
	assert.Equal(t, "LINK", TokenQualifier("LINK"))
	assert.Equal(t, "", TokenQualifier(""))
}
