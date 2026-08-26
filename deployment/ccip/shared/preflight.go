package shared

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

// PlannedRef is one datastore row a changeset intends to write, named by the part of the key
// that is knowable before anything is deployed.
//
// The datastore key is (chainSelector, type, version, qualifier): a changeset can state exactly
// which keys it will occupy before it deploys anything, even though it cannot yet know the addresses.
type PlannedRef struct {
	ChainSelector uint64
	Type          cldf.ContractType
	Version       semver.Version
	Qualifier     string
	// MultiInstance declares that this type can exist more than once per chain, so an empty
	// qualifier is a bug rather than the singleton default.
	MultiInstance bool
	// Address is optional: deploy changesets plan their keys before anything is on chain,
	// when the address is not yet knowable. Import-style callers that do know it get the
	// re-record rule: when the key already points at this address, the write is a no-op, not
	// a conflict. The comparison is exact Aptos addresses are written in their canonical
	// StringLong form.
	Address string
}

func (r PlannedRef) key() string {
	return fmt.Sprintf("%d|%s|%s|%s", r.ChainSelector, r.Type, r.Version.String(), r.Qualifier)
}

func (r PlannedRef) describe() string {
	if r.Qualifier == "" {
		return fmt.Sprintf("%s %s on chain %d (no qualifier)", r.Type, r.Version.String(), r.ChainSelector)
	}
	return fmt.Sprintf("%s %s on chain %d qualified %q", r.Type, r.Version.String(), r.ChainSelector, r.Qualifier)
}

// ValidatePlannedRefs checks that the refs a changeset is about to write can be recorded in
// the datastore, and is meant to be called from VerifyPreconditions before any transaction
// is signed or staged. A conflict caught there costs a re-run; the same conflict discovered
// during Apply means the contracts are already deployed on chain, and since a changeset that
// fails mid-way returns an empty ChangesetOutput, every address it had recorded up to that
// point is discarded too.
//
// It reports every problem it finds:
//   - a multi-instance ref with no qualifier, which would collide with its siblings;
//   - two planned refs sharing one datastore key;
//   - a planned key already taken in the environment, where recording the new address would
//     silently replace the existing one (MemoryDataStore.Merge upserts).
//
// An occupied key is an error unless replaceExisting says the caller means to take it.
// That intent has to be stated rather than inferred: the two cases are indistinguishable
// from the datastore's side, and the framework resolves them identically and silently.
// When the caller opts in, each displaced address is logged.
//
// Callers must declare only the refs they will actually deploy on this run, mirroring the
// conditionals in Apply, so that an existing key always means a genuine conflict.
//
// Two things this cannot see, both structural. It compares against the environment datastore
// as it stands before the changeset runs, so it will not catch two changesets in the same
// pipeline claiming one key that collision only materialises when their outputs are
// merged. And on a chain whose datastore is empty the check is vacuous: rows recorded under
// an earlier qualifier scheme occupy different keys, so the re-qualification tooling owns
// retiring them.
func ValidatePlannedRefs(env cldf.Environment, replaceExisting bool, planned []PlannedRef) error {
	var errs []error
	seen := make(map[string]struct{}, len(planned))
	for _, ref := range planned {
		if ref.MultiInstance && ref.Qualifier == "" {
			errs = append(errs, fmt.Errorf(
				"%s is multi-instance and needs a qualifier: without one it shares a datastore key with every other %s on that chain",
				ref.describe(), ref.Type))
		}
		if _, duplicate := seen[ref.key()]; duplicate {
			errs = append(errs, fmt.Errorf(
				"two planned refs map to the same datastore key (chain=%d, type=%s, version=%s, qualifier=%q); give each instance its own qualifier",
				ref.ChainSelector, ref.Type, ref.Version.String(), ref.Qualifier))
		}
		seen[ref.key()] = struct{}{}
	}

	if env.DataStore == nil {
		return errors.Join(errs...)
	}

	type conflict struct {
		planned  PlannedRef
		existing string
	}
	var conflicts []conflict
	for _, ref := range planned {
		version := ref.Version
		existing, err := env.DataStore.Addresses().Get(
			datastore.NewAddressRefKey(ref.ChainSelector, datastore.ContractType(ref.Type), &version, ref.Qualifier))
		switch {
		case errors.Is(err, datastore.ErrAddressRefNotFound):
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("failed to look up planned ref %s: %w", ref.key(), err))
			continue
		}
		if ref.Address != "" && ref.Address == existing.Address {
			// Re-recording the contract the key already points at: a no-op, not a takeover.
			continue
		}
		conflicts = append(conflicts, conflict{planned: ref, existing: existing.Address})
	}
	if len(conflicts) == 0 {
		return errors.Join(errs...)
	}
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].planned.key() < conflicts[j].planned.key() })

	if replaceExisting {
		if env.Logger != nil {
			for _, c := range conflicts {
				env.Logger.Warnw("replacing an existing datastore ref",
					"chainSelector", c.planned.ChainSelector,
					"ref", c.planned.describe(),
					"replacedAddress", c.existing)
			}
		}
		return errors.Join(errs...)
	}

	for _, c := range conflicts {
		errs = append(errs, fmt.Errorf(
			"datastore conflict: %s is already held by %s; nothing has been deployed. If this is an intentional redeploy, set the changeset's ReplaceExisting flag; otherwise the qualifiers are wrong — two different contracts cannot share one (chain, type, version, qualifier)",
			c.planned.describe(), c.existing))
	}
	return errors.Join(errs...)
}
