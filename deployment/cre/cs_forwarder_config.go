package cre

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	adapterbind "github.com/smartcontractkit/chainlink-aptos/bindings/forwarder_mcms_adapter"
)

var (
	_ cldf.ChangeSetV2[SetForwarderConfigConfig]   = SetForwarderConfig{}
	_ cldf.ChangeSetV2[ClearForwarderConfigConfig] = ClearForwarderConfig{}
)

// ownedForwarder is a zone's forwarder checked to be owned by the party that will act on it:
// the deployer (direct mode) or the adapter's MCMS owner account (MCMS mode).
type ownedForwarder struct {
	chain cldf_aptos.Chain
	fwd   forwarder
	gov   governance // MCMS mode only
}

func loadOwnedForwarder(env cldf.Environment, chainSelector uint64, qualifier string, zone Zone, mcms *cldfproposalutils.TimelockConfig) (ownedForwarder, error) {
	chain, err := aptosChain(env, chainSelector)
	if err != nil {
		return ownedForwarder{}, err
	}
	if err := zone.Validate(); err != nil {
		return ownedForwarder{}, err
	}
	fwd, err := loadForwarder(env, chain, zone)
	if err != nil {
		return ownedForwarder{}, err
	}
	out := ownedForwarder{chain: chain, fwd: fwd}

	var owner aptos.AccountAddress
	var ownerDesc string
	if mcms != nil {
		out.gov, err = loadGovernance(env, chain, qualifierOrDefault(qualifier))
		if err != nil {
			return ownedForwarder{}, err
		}
		owner, ownerDesc = out.gov.adapter.owner, "the adapter's MCMS owner account; hand the forwarder to MCMS first or run without MCMS"
	} else {
		owner, err = deployerAddress(chain)
		if err != nil {
			return ownedForwarder{}, err
		}
		ownerDesc = "the deployer; once MCMS owns the forwarder, run with MCMS set"
	}
	if err := fwd.requireOwner(owner, ownerDesc); err != nil {
		return ownedForwarder{}, err
	}
	return out, nil
}

// SetForwarderConfig sets a DON's config (signers and F) on one zone's forwarder. The signers are
// the DON nodes' Aptos OCR2 onchain signing keys from the job distributor.
//
//   - Direct (MCMS unset): the deployer sends set_config; the forwarder must be deployer-owned.
//   - MCMS: an MCMS proposal calls set_config through the adapter; the forwarder must be owned by
//     the adapter's MCMS owner account.
type SetForwarderConfig struct{}

type setConfigPlan struct {
	ownedForwarder
	oracles [][]byte
}

func planSetConfig(env cldf.Environment, cfg SetForwarderConfigConfig) (setConfigPlan, error) {
	if err := cfg.DON.Validate(); err != nil {
		return setConfigPlan{}, err
	}
	owned, err := loadOwnedForwarder(env, cfg.ChainSelector, cfg.Qualifier, cfg.Zone, cfg.MCMS)
	if err != nil {
		return setConfigPlan{}, err
	}
	oracles, err := resolveSigners(env.GetContext(), env.Offchain, cfg.ChainSelector, cfg.DON.NodeIDs)
	if err != nil {
		return setConfigPlan{}, fmt.Errorf("resolve DON signers: %w", err)
	}
	if err := validateSignerCount(cfg.DON.F, len(oracles)); err != nil {
		return setConfigPlan{}, err
	}
	return setConfigPlan{ownedForwarder: owned, oracles: oracles}, nil
}

func (SetForwarderConfig) VerifyPreconditions(env cldf.Environment, cfg SetForwarderConfigConfig) error {
	_, err := planSetConfig(env, cfg)
	return err
}

func (SetForwarderConfig) Apply(env cldf.Environment, cfg SetForwarderConfigConfig) (cldf.ChangesetOutput, error) {
	plan, err := planSetConfig(env, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	fwd := plan.fwd
	logArgs := []any{"zone", fwd.zone, "forwarder", fwd.address.StringLong(), "donID", cfg.DON.ID, "configVersion", cfg.DON.ConfigVersion, "f", cfg.DON.F, "signers", len(plan.oracles)}

	if cfg.MCMS == nil {
		tx, err := fwd.contract.SetConfig(deployerOpts(plan.chain), cfg.DON.ID, cfg.DON.ConfigVersion, cfg.DON.F, plan.oracles)
		if err := confirm(plan.chain, tx, err, fmt.Sprintf("set_config on %s forwarder %s", fwd.zone, fwd.address.StringLong())); err != nil {
			return cldf.ChangesetOutput{}, err
		}
		env.Logger.Infow("Set forwarder config", logArgs...)
		return cldf.ChangesetOutput{}, nil
	}

	tx, err := adapterTx(adapterbind.NewEncoder(plan.gov.adapter.address).SetConfig(fwd.address, cfg.DON.ID, cfg.DON.ConfigVersion, cfg.DON.F, plan.oracles))
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	env.Logger.Infow("Built governed forwarder set_config proposal", logArgs...)
	return proposalOutput(env, cfg.ChainSelector, plan.gov.mcms, singleBatch(cfg.ChainSelector, []mcmstypes.Transaction{tx}),
		fmt.Sprintf("Set DON %d config %d on the %s CRE forwarder", cfg.DON.ID, cfg.DON.ConfigVersion, fwd.zone), *cfg.MCMS)
}

// ClearForwarderConfig removes a DON config from one zone's forwarder, directly or through MCMS
// (same ownership rules as SetForwarderConfig).
type ClearForwarderConfig struct{}

func planClearConfig(env cldf.Environment, cfg ClearForwarderConfigConfig) (ownedForwarder, error) {
	owned, err := loadOwnedForwarder(env, cfg.ChainSelector, cfg.Qualifier, cfg.Zone, cfg.MCMS)
	if err != nil {
		return ownedForwarder{}, err
	}
	exists, err := owned.fwd.configExists(owned.chain.Client, cfg.DONID, cfg.ConfigVersion)
	if err != nil {
		return ownedForwarder{}, err
	}
	if !exists {
		return ownedForwarder{}, fmt.Errorf("%s forwarder %s has no config for DON %d version %d", cfg.Zone, owned.fwd.address.StringLong(), cfg.DONID, cfg.ConfigVersion)
	}
	return owned, nil
}

func (ClearForwarderConfig) VerifyPreconditions(env cldf.Environment, cfg ClearForwarderConfigConfig) error {
	_, err := planClearConfig(env, cfg)
	return err
}

func (ClearForwarderConfig) Apply(env cldf.Environment, cfg ClearForwarderConfigConfig) (cldf.ChangesetOutput, error) {
	plan, err := planClearConfig(env, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	fwd := plan.fwd

	if cfg.MCMS == nil {
		tx, err := fwd.contract.ClearConfig(deployerOpts(plan.chain), cfg.DONID, cfg.ConfigVersion)
		if err := confirm(plan.chain, tx, err, fmt.Sprintf("clear_config on %s forwarder %s", fwd.zone, fwd.address.StringLong())); err != nil {
			return cldf.ChangesetOutput{}, err
		}
		env.Logger.Infow("Cleared forwarder config", "zone", fwd.zone, "forwarder", fwd.address.StringLong(), "donID", cfg.DONID, "configVersion", cfg.ConfigVersion)
		return cldf.ChangesetOutput{}, nil
	}

	tx, err := adapterTx(adapterbind.NewEncoder(plan.gov.adapter.address).ClearConfig(fwd.address, cfg.DONID, cfg.ConfigVersion))
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	return proposalOutput(env, cfg.ChainSelector, plan.gov.mcms, singleBatch(cfg.ChainSelector, []mcmstypes.Transaction{tx}),
		fmt.Sprintf("Clear DON %d config %d on the %s CRE forwarder", cfg.DONID, cfg.ConfigVersion, fwd.zone), *cfg.MCMS)
}
