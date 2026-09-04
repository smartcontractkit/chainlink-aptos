package testutil

import (
	"fmt"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	mcmsTypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldftesthelpers "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils/testhelpers"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-evm/pkg/utils"
)

// ConfiguredChangeSet is a changeset plus config ready to apply in tests.
type ConfiguredChangeSet interface {
	Apply(e cldf.Environment) (cldf.ChangesetOutput, error)
}

// Configure wraps a ChangeSetV2 with its config for test application.
func Configure[C any](changeset cldf.ChangeSetV2[C], config C) ConfiguredChangeSet {
	return configuredChangeSetImpl[C]{
		changeset: changeset,
		config:    config,
	}
}

type configuredChangeSetImpl[C any] struct {
	changeset cldf.ChangeSetV2[C]
	config    C
}

func (ca configuredChangeSetImpl[C]) Apply(e cldf.Environment) (cldf.ChangesetOutput, error) {
	if err := ca.changeset.VerifyPreconditions(e, ca.config); err != nil {
		return cldf.ChangesetOutput{}, err
	}
	return ca.changeset.Apply(e, ca.config)
}

// Apply applies one or more configured changesets and executes any MCMS proposals.
func Apply(t *testing.T, e cldf.Environment, first ConfiguredChangeSet, rest ...ConfiguredChangeSet) (cldf.Environment, error) {
	env, _, err := ApplyChangesets(t, e, append([]ConfiguredChangeSet{first}, rest...))
	return env, err
}

type applyChangesetOptions struct {
	realBackend bool
}

// ApplyChangesetsOptions configures ApplyChangesets behavior.
type ApplyChangesetsOptions func(*applyChangesetOptions) *applyChangesetOptions

// WithRealBackend uses real chain backends when executing MCMS proposals.
func WithRealBackend() ApplyChangesetsOptions {
	return func(o *applyChangesetOptions) *applyChangesetOptions {
		o.realBackend = true
		return o
	}
}

// ApplyChangesets applies configured changesets and signs/executes MCMS proposals.
func ApplyChangesets(t *testing.T, e cldf.Environment, changesetApplications []ConfiguredChangeSet, opts ...ApplyChangesetsOptions) (cldf.Environment, []cldf.ChangesetOutput, error) {
	opt := applyChangesetOptions{}
	for _, o := range opts {
		opt = *o(&opt)
	}

	currentEnv := e
	outputs := make([]cldf.ChangesetOutput, 0, len(changesetApplications))
	for i, csa := range changesetApplications {
		out, err := csa.Apply(currentEnv)
		if err != nil {
			return e, nil, fmt.Errorf("failed to apply changeset at index %d: %w", i, err)
		}
		outputs = append(outputs, out)

		var addresses cldf.AddressBook
		if out.AddressBook != nil {
			addresses = out.AddressBook
			if err := addresses.Merge(currentEnv.ExistingAddresses); err != nil {
				return e, nil, fmt.Errorf("failed to merge address book: %w", err)
			}
		} else {
			addresses = currentEnv.ExistingAddresses
		}

		var ds datastore.DataStore
		if out.DataStore != nil {
			// Existing state first, then the changeset output on top: MemoryDataStore.Merge
			// upserts, so the last writer of a (chain, type, version, qualifier) key wins,
			// and freshly deployed refs must win over stale ones.
			ds1 := datastore.NewMemoryDataStore()
			if currentEnv.DataStore != nil {
				if err := ds1.Merge(currentEnv.DataStore); err != nil {
					return e, nil, fmt.Errorf("failed to merge current addresses into datastore: %w", err)
				}
			}
			if err := ds1.Merge(out.DataStore.Seal()); err != nil {
				return e, nil, fmt.Errorf("failed to merge new addresses into datastore: %w", err)
			}
			ds = ds1.Seal()
		} else {
			ds = currentEnv.DataStore
		}

		currentEnv = cldf.Environment{
			Name:              e.Name,
			Logger:            e.Logger,
			ExistingAddresses: addresses,
			DataStore:         ds,
			NodeIDs:           e.NodeIDs,
			Offchain:          e.Offchain,
			OCRSecrets:        e.OCRSecrets,
			GetContext:        e.GetContext,
			OperationsBundle:  operations.NewBundle(e.GetContext, e.Logger, operations.NewMemoryReporter()),
			BlockChains:       e.BlockChains,
		}

		for _, prop := range out.MCMSTimelockProposals {
			chains := mapset.NewSet[uint64]()
			for _, op := range prop.Operations {
				chains.Add(uint64(op.ChainSelector))
			}

			saltOverride := utils.RandomHash()
			prop.SaltOverride = &saltOverride

			p := cldftesthelpers.SignMCMSTimelockProposal(t, currentEnv, &prop, opt.realBackend)
			if err := cldftesthelpers.ExecuteMCMSProposalV2(t, currentEnv, p); err != nil {
				return cldf.Environment{}, nil, err
			}
			if prop.Action != mcmsTypes.TimelockActionSchedule {
				return currentEnv, outputs, nil
			}
			if err := cldftesthelpers.ExecuteMCMSTimelockProposalV2(t, currentEnv, &prop); err != nil {
				return cldf.Environment{}, nil, err
			}
		}

		for _, prop := range out.MCMSProposals {
			p := cldftesthelpers.SignMCMSProposal(t, currentEnv, &prop)
			if err := cldftesthelpers.ExecuteMCMSProposalV2(t, currentEnv, p); err != nil {
				return cldf.Environment{}, nil, err
			}
		}
	}

	return currentEnv, outputs, nil
}
