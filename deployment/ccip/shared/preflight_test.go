package shared

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

var version1_6_0 = *semver.MustParse("1.6.0")

const (
	chainA uint64 = 743186221051783445
	chainB uint64 = 4457093679053095497

	poolA  = "0x1111111111111111111111111111111111111111111111111111111111111111"
	poolB  = "0x2222222222222222222222222222222222222222222222222222222222222222"
	ccipAd = "0x3333333333333333333333333333333333333333333333333333333333333333"
)

func bookWith(t *testing.T, entries map[uint64]map[string]cldf.TypeAndVersion) cldf.AddressBook {
	t.Helper()
	ab := cldf.NewMemoryAddressBook()
	for chainSelector, addresses := range entries {
		for address, typeAndVersion := range addresses {
			require.NoError(t, ab.Save(chainSelector, address, typeAndVersion))
		}
	}
	return ab
}

func existingStore(t *testing.T, refs ...datastore.AddressRef) datastore.DataStore {
	t.Helper()
	ds := datastore.NewMemoryDataStore()
	for _, ref := range refs {
		require.NoError(t, ds.Addresses().Add(ref))
	}
	return ds.Seal()
}

func poolRef(qualifier string) PlannedRef {
	return PlannedRef{
		ChainSelector: chainA,
		Type:          AptosManagedTokenPoolType,
		Version:       version1_6_0,
		Qualifier:     qualifier,
		MultiInstance: true,
	}
}

func TestValidatePlannedRefs_FreeKeysPass(t *testing.T) {
	env := cldf.Environment{DataStore: existingStore(t, datastore.AddressRef{
		ChainSelector: chainA,
		Address:       poolA,
		Type:          datastore.ContractType(AptosManagedTokenPoolType),
		Version:       &version1_6_0,
		Qualifier:     "LINK",
	})}

	err := ValidatePlannedRefs(env, false, []PlannedRef{
		poolRef("USDC"),
		// A chain singleton legitimately plans an empty qualifier.
		{ChainSelector: chainA, Type: AptosCCIPType, Version: version1_6_0},
	})

	require.NoError(t, err)
}

func TestValidatePlannedRefs_MultiInstanceNeedsQualifier(t *testing.T) {
	err := ValidatePlannedRefs(cldf.Environment{}, false, []PlannedRef{poolRef("")})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "is multi-instance and needs a qualifier")
}

func TestValidatePlannedRefs_DuplicatePlannedKeys(t *testing.T) {
	err := ValidatePlannedRefs(cldf.Environment{}, false, []PlannedRef{poolRef("LINK"), poolRef("LINK")})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "two planned refs map to the same datastore key")
}

// The case this guards: the deploy would succeed on chain and the new ref would then replace
// the recorded one on merge, silently dropping an address.
func TestValidatePlannedRefs_KeyAlreadyTaken(t *testing.T) {
	env := cldf.Environment{DataStore: existingStore(t, datastore.AddressRef{
		ChainSelector: chainA,
		Address:       poolA,
		Type:          datastore.ContractType(AptosManagedTokenPoolType),
		Version:       &version1_6_0,
		Qualifier:     "LINK",
	})}

	err := ValidatePlannedRefs(env, false, []PlannedRef{poolRef("LINK")})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "datastore conflict")
	assert.Contains(t, err.Error(), poolA)
	// The error must point the operator at the escape hatch.
	assert.Contains(t, err.Error(), "ReplaceExisting")
}

// An intentional redeploy may take an occupied key, but the takeover is always announced.
func TestValidatePlannedRefs_ReplaceExistingTakesTheKey(t *testing.T) {
	env := cldf.Environment{DataStore: existingStore(t, datastore.AddressRef{
		ChainSelector: chainA,
		Address:       poolA,
		Type:          datastore.ContractType(AptosManagedTokenPoolType),
		Version:       &version1_6_0,
		Qualifier:     "LINK",
	})}

	require.NoError(t, ValidatePlannedRefs(env, true, []PlannedRef{poolRef("LINK")}))
}

// replaceExisting licenses takeovers, not changeset bugs: two planned refs on one key would
// still collide at write time, after the first contract is already on chain.
func TestValidatePlannedRefs_ReplaceExistingStillRejectsPlanDuplicates(t *testing.T) {
	err := ValidatePlannedRefs(cldf.Environment{}, true, []PlannedRef{poolRef("LINK"), poolRef("LINK")})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "two planned refs map to the same datastore key")
}

// An import-style ref that names the address the key already points at is a re-record, not
// a takeover.
func TestValidatePlannedRefs_RecordingTheSameAddressIsNotAConflict(t *testing.T) {
	env := cldf.Environment{DataStore: existingStore(t, datastore.AddressRef{
		ChainSelector: chainA,
		Address:       poolA,
		Type:          datastore.ContractType(AptosManagedTokenPoolType),
		Version:       &version1_6_0,
		Qualifier:     "LINK",
	})}
	reRecord := poolRef("LINK")
	reRecord.Address = poolA

	require.NoError(t, ValidatePlannedRefs(env, false, []PlannedRef{reRecord}))
}

// The same key on another chain is a different key.
func TestValidatePlannedRefs_ExistingRefOnAnotherChainIsNotAConflict(t *testing.T) {
	env := cldf.Environment{DataStore: existingStore(t, datastore.AddressRef{
		ChainSelector: chainB,
		Address:       poolA,
		Type:          datastore.ContractType(AptosManagedTokenPoolType),
		Version:       &version1_6_0,
		Qualifier:     "LINK",
	})}

	require.NoError(t, ValidatePlannedRefs(env, false, []PlannedRef{poolRef("LINK")}))
}

func TestValidatePlannedRefs_NilDataStorePasses(t *testing.T) {
	require.NoError(t, ValidatePlannedRefs(cldf.Environment{}, false, []PlannedRef{poolRef("LINK")}))
}
