package shared

import (
	"errors"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// RecordAddress writes one contract address to both the legacy address book and the
// datastore, deriving identical metadata from one TypeAndVersion so the two stores cannot
// drift. The datastore AddressRef copies the address-book labels (token symbol, token
// address) so the state loader reconstructs the same TypeAndVersion without RPC.
//
// Writes are ordered so a failure touches as little as possible: the datastore key is
// checked read-only first, then the address book is written (idempotently), then the
// datastore. The datastore write uses Add, not Upsert: within one changeset run, writing one
// key twice with different addresses is always a bug — Upsert would drop the first ref and
// report success, leaving a contract on chain that the registry never mentions. Conflicts
// with rows written by *previous* runs cannot be seen here (the datastore passed in is the
// changeset's own output store) — those are checked upfront by ValidatePlannedRefs, before
// anything is deployed.
func RecordAddress(ab cldf.AddressBook, ds datastore.MutableDataStore, chainSelector uint64, address string, tv cldf.TypeAndVersion, qualifier string) error {
	if address == "" {
		return fmt.Errorf("cannot record %s %s on chain %d: address is empty", tv.Type, tv.Version, chainSelector)
	}
	if qualifier != "" && strings.Contains(strings.ToLower(qualifier), strings.ToLower(address)) {
		return fmt.Errorf(
			"qualifier %q for %s contains the address being written: a qualifier must identify the instance in domain terms, not by its own address",
			qualifier, tv.Type)
	}
	if ds == nil {
		return fmt.Errorf("cannot record %s %s on chain %d: datastore is nil", tv.Type, tv.Version, chainSelector)
	}

	version := tv.Version
	ref := datastore.AddressRef{
		ChainSelector: chainSelector,
		Address:       address,
		Type:          datastore.ContractType(tv.Type),
		Version:       &version,
		Qualifier:     qualifier,
	}
	if !tv.Labels.IsEmpty() {
		ref.Labels = datastore.NewLabelSet(tv.Labels.List()...)
	}

	datastoreAlreadyRecorded := false

	// Check the datastore key read-only, before either store is written. Re-recording the
	// contract the key already points at is idempotent; a different address under the same
	// key is a bug in the changeset, reported with neither store touched.
	existing, err := ds.Addresses().Get(ref.Key())
	switch {
	case err == nil:
		if existing.Address == address {
			datastoreAlreadyRecorded = true
			break
		}
		return fmt.Errorf(
			"this changeset already recorded %s under (chain=%d, type=%s, version=%s, qualifier=%q): two contracts cannot share one datastore key, so one of them needs a distinct qualifier",
			existing.Address, chainSelector, tv.Type, tv.Version, qualifier)
	case errors.Is(err, datastore.ErrAddressRefNotFound):
	default:
		return fmt.Errorf("checking datastore for %s %s on chain %d: %w", tv.Type, tv.Version, chainSelector, err)
	}

	// Address book write, idempotent: AddressBookMap.Save rejects repeats outright, so a
	// repeat of the same address with the same type/version is skipped; the same address
	// with a different type/version is an error and leaves the datastore untouched. Some
	// callers only need the datastore side (for example, a derived-address path), so a nil
	// address book is explicitly supported.
	if ab != nil {
		chainAddresses, err := ab.AddressesForChain(chainSelector)
		if err != nil && !errors.Is(err, cldf.ErrChainNotFound) {
			return fmt.Errorf("reading address book for chain %d: %w", chainSelector, err)
		}
		if existingTV, ok := chainAddresses[address]; ok {
			if existingTV.Type != tv.Type || !existingTV.Version.Equal(&tv.Version) {
				return fmt.Errorf(
					"address book already holds %s on chain %d as %s, cannot also record it as %s; datastore left untouched",
					address, chainSelector, existingTV.String(), tv.String())
			}
		} else if err := ab.Save(chainSelector, address, tv); err != nil {
			return fmt.Errorf("save to address book: %w", err)
		}
	}

	if datastoreAlreadyRecorded {
		return nil
	}

	if err := ds.Addresses().Add(ref); err != nil {
		return fmt.Errorf("save to datastore: %w", err)
	}
	return nil
}
