package cre

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	adapterbind "github.com/smartcontractkit/chainlink-aptos/bindings/forwarder_mcms_adapter"
	mcmsbind "github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
)

var _ cldf.ChangeSetV2[DeployForwarderAdapterConfig] = DeployForwarderAdapter{}

// DeployForwarderAdapter publishes forwarder_mcms_adapter through the CRE MCMS (mcms_deployer),
// compiled against the zone-a and zone-b forwarders from the datastore. Publishing through MCMS
// makes the adapter's code object owned by MCMS from the start, so only MCMS can upgrade it (the
// adapter's init_module refuses any other publisher).
//
// Output: a proposal that stages and publishes the package, plus datastore refs for the adapter
// and its MCMS owner account. That owner account is the address both forwarders must be
// transferred to (TransferForwarderOwnership, or the native multisig's own proposal).
type DeployForwarderAdapter struct{}

func (DeployForwarderAdapter) VerifyPreconditions(env cldf.Environment, cfg DeployForwarderAdapterConfig) error {
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return err
	}
	qualifier := qualifierOrDefault(cfg.Qualifier)
	var errs []error

	mcmsAddr, err := mcmsAddress(env, cfg.ChainSelector, qualifier)
	if err != nil {
		errs = append(errs, err)
	} else if owned, err := mcmsSelfOwned(chain.Client, mcmsAddr); err != nil {
		errs = append(errs, err)
	} else if !owned {
		errs = append(errs, fmt.Errorf("MCMS %s does not own itself yet: execute the DeployCREMCMS proposal (accept ownership) first; mcms_deployer only publishes for a self-owned MCMS", mcmsAddr.StringLong()))
	}

	if _, err := zoneForwarders(env, chain); err != nil {
		errs = append(errs, err)
	}

	if cfg.Seed != "" && mcmsAddr != (aptos.AccountAddress{}) {
		addr, err := mcmsbind.Bind(mcmsAddr, chain.Client).MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(cfg.Seed))
		if err != nil {
			errs = append(errs, fmt.Errorf("derive adapter address for seed %q: %w", cfg.Seed, err))
		} else if _, err := chain.Client.AccountResource(addr, "0x1::object::ObjectCore"); err == nil {
			errs = append(errs, fmt.Errorf("seed %q was already used: object %s exists; pick a new seed", cfg.Seed, addr.StringLong()))
		}
	}

	errs = append(errs, shared.ValidatePlannedRefs(env, false, adapterPlannedRefs(cfg.ChainSelector, qualifier)))
	return errors.Join(errs...)
}

func adapterPlannedRefs(chainSelector uint64, qualifier string) []shared.PlannedRef {
	return []shared.PlannedRef{
		{ChainSelector: chainSelector, Type: AptosForwarderMcmsAdapterType, Version: Version1_0_0, Qualifier: qualifier, MultiInstance: true},
		{ChainSelector: chainSelector, Type: AptosForwarderMcmsAdapterOwnerType, Version: Version1_0_0, Qualifier: qualifier, MultiInstance: true},
	}
}

// zoneForwarders resolves both forwarders and checks that each is the forwarder package its zone
// expects. Publishing would fail anyway on a package-name mismatch (dependency check), but this
// catches a wrong datastore ref before anything is proposed.
func zoneForwarders(env cldf.Environment, chain cldf_aptos.Chain) (map[Zone]forwarder, error) {
	out := make(map[Zone]forwarder, len(AllZones))
	var errs []error
	for _, zone := range AllZones {
		fwd, err := loadForwarder(env, chain, zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		names, err := packageNames(chain.Client, fwd.address)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s forwarder %s: %w", zone, fwd.address.StringLong(), err))
			continue
		}
		if !slices.Contains(names, zone.onChainPackageName()) {
			errs = append(errs, fmt.Errorf("%s forwarder %s hosts packages %v, expected %s", zone, fwd.address.StringLong(), names, zone.onChainPackageName()))
			continue
		}
		out[zone] = fwd
	}
	if len(out) == len(AllZones) && out[ZoneA].address == out[ZoneB].address {
		same := out[ZoneA].address
		errs = append(errs, fmt.Errorf("zone-a and zone-b forwarders are both %s", same.StringLong()))
	}
	return out, errors.Join(errs...)
}

func (DeployForwarderAdapter) Apply(env cldf.Environment, cfg DeployForwarderAdapterConfig) (cldf.ChangesetOutput, error) {
	qualifier := qualifierOrDefault(cfg.Qualifier)
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	mcmsAddr, err := mcmsAddress(env, cfg.ChainSelector, qualifier)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	fwds, err := zoneForwarders(env, chain)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	seed := cfg.Seed
	if seed == "" {
		seed = fmt.Sprintf("forwarder_mcms_adapter_%d", time.Now().UnixNano())
	}
	mcmsContract := mcmsbind.Bind(mcmsAddr, chain.Client)
	adapterAddr, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(seed))
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("derive adapter address: %w", err)
	}
	ownerAddr, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(seed))
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("derive adapter owner address: %w", err)
	}

	// owner/owner_secondary only satisfy the forwarder dependencies' named addresses; use the
	// forwarders' current owners so the compiled dependencies match what is deployed.
	primaryOwner, err := fwds[ZoneA].owner()
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	secondaryOwner, err := fwds[ZoneB].owner()
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	payload, err := adapterbind.Compile(adapterbind.NamedAddresses{
		Adapter:           adapterAddr,
		MCMS:              mcmsAddr,
		Platform:          fwds[ZoneA].address,
		PlatformSecondary: fwds[ZoneB].address,
		Owner:             primaryOwner,
		OwnerSecondary:    secondaryOwner,
	})
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("compile forwarder_mcms_adapter: %w", err)
	}

	var batches []mcmstypes.BatchOperation
	cleanup, err := cleanupStagingBatch(chain, mcmsContract)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	batches = append(batches, cleanup...)
	publishOps, err := utils.CreateChunksAndStage(payload, mcmsContract, cfg.ChainSelector, seed, nil)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("create publish operations: %w", err)
	}
	batches = append(batches, utils.ToBatchOperations(publishOps)...)

	ds := datastore.NewMemoryDataStore()
	if err := shared.RecordAddress(nil, ds, cfg.ChainSelector, adapterAddr.StringLong(), cldf.NewTypeAndVersion(AptosForwarderMcmsAdapterType, Version1_0_0), qualifier); err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("record adapter: %w", err)
	}
	if err := shared.RecordAddress(nil, ds, cfg.ChainSelector, ownerAddr.StringLong(), cldf.NewTypeAndVersion(AptosForwarderMcmsAdapterOwnerType, Version1_0_0), qualifier); err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("record adapter owner: %w", err)
	}
	primaryAddr, secondaryAddr := fwds[ZoneA].address, fwds[ZoneB].address
	env.Logger.Infow("Proposed forwarder_mcms_adapter publish; after it executes, transfer both forwarders to the adapter owner",
		"chainSelector", cfg.ChainSelector, "adapter", adapterAddr.StringLong(), "adapterOwner", ownerAddr.StringLong(),
		"seed", seed, "zone-a", primaryAddr.StringLong(), "zone-b", secondaryAddr.StringLong())

	out, err := proposalOutput(env, cfg.ChainSelector, mcmsAddr, batches, "Publish forwarder_mcms_adapter for the CRE forwarders", cfg.TimelockConfig)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	out.DataStore = ds
	return out, nil
}

// cleanupStagingBatch returns a batch clearing a leftover mcms_deployer staging area, or nothing
// when it is already clean. It reads chain state directly rather than through the CCIP
// operation, whose report could be replayed after the area was cleaned.
func cleanupStagingBatch(chain cldf_aptos.Chain, mcmsContract mcmsbind.MCMS) ([]mcmstypes.BatchOperation, error) {
	clean, err := utils.IsMCMSStagingAreaClean(chain.Client, mcmsContract.Address())
	if err != nil {
		return nil, fmt.Errorf("check MCMS staging area: %w", err)
	}
	if clean {
		return nil, nil
	}
	module, function, _, args, err := mcmsContract.MCMSDeployer().Encoder().CleanupStagingArea()
	if err != nil {
		return nil, fmt.Errorf("encode cleanup_staging_area: %w", err)
	}
	tx, err := utils.GenerateMCMSTx(mcmsContract.Address(), module, function, args)
	if err != nil {
		return nil, err
	}
	if tx.Data == nil {
		tx.Data = []byte{}
	}
	return singleBatch(chain.Selector, []mcmstypes.Transaction{tx}), nil
}
