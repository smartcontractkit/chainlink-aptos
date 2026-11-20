package cre

import (
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	adapterbind "github.com/smartcontractkit/chainlink-aptos/bindings/forwarder_mcms_adapter"
)

var (
	_ cldf.ChangeSetV2[TransferForwarderOwnershipConfig] = TransferForwarderOwnership{}
	_ cldf.ChangeSetV2[AcceptForwarderOwnershipConfig]   = AcceptForwarderOwnership{}
)

// TransferForwarderOwnership proposes a new owner for the selected forwarders (the first step of
// the forwarder's two-step ownership transfer).
//
//   - Direct (MCMS unset): the deployer, which must own the forwarders, proposes To, by default
//     the adapter's MCMS owner account. This is the staging handover to MCMS. Forwarders owned by
//     a native multisig are handed over with that multisig's own tooling instead.
//   - MCMS: the adapter's MCMS owner account, which must own the forwarders, proposes To (required)
//     through an MCMS proposal. This hands forwarders back out of MCMS.
type TransferForwarderOwnership struct{}

type transferPlan struct {
	chain cldf_aptos.Chain
	fwds  []forwarder
	to    aptos.AccountAddress
	gov   governance // MCMS mode only
}

func planTransfer(env cldf.Environment, cfg TransferForwarderOwnershipConfig) (transferPlan, error) {
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return transferPlan{}, err
	}
	zones, err := zonesOrAll(cfg.Zones)
	if err != nil {
		return transferPlan{}, err
	}
	qualifier := qualifierOrDefault(cfg.Qualifier)
	plan := transferPlan{chain: chain}

	if cfg.To != "" {
		if err := plan.to.ParseStringRelaxed(cfg.To); err != nil {
			return transferPlan{}, fmt.Errorf("invalid To address %q: %w", cfg.To, err)
		}
	}

	var current aptos.AccountAddress
	var currentDesc string
	if cfg.MCMS != nil {
		plan.gov, err = loadGovernance(env, chain, qualifier)
		if err != nil {
			return transferPlan{}, err
		}
		if cfg.To == "" {
			return transferPlan{}, errors.New("To is required in MCMS mode (the owner to hand the forwarders to)")
		}
		current, currentDesc = plan.gov.adapter.owner, "the adapter's MCMS owner account"
	} else {
		current, err = deployerAddress(chain)
		if err != nil {
			return transferPlan{}, err
		}
		currentDesc = "the deployer"
		if cfg.To == "" {
			adapter, err := loadAdapter(env, chain, qualifier)
			if err != nil {
				return transferPlan{}, fmt.Errorf("To defaults to the adapter's MCMS owner account, but the adapter could not be loaded: %w", err)
			}
			plan.to = adapter.owner
		}
	}
	if plan.to == current {
		return transferPlan{}, fmt.Errorf("forwarders would be transferred to their current owner %s", current.StringLong())
	}

	var errs []error
	for _, zone := range zones {
		fwd, err := loadForwarder(env, chain, zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := fwd.requireOwner(current, currentDesc); err != nil {
			errs = append(errs, err)
			continue
		}
		plan.fwds = append(plan.fwds, fwd)
	}
	return plan, errors.Join(errs...)
}

func (TransferForwarderOwnership) VerifyPreconditions(env cldf.Environment, cfg TransferForwarderOwnershipConfig) error {
	_, err := planTransfer(env, cfg)
	return err
}

func (TransferForwarderOwnership) Apply(env cldf.Environment, cfg TransferForwarderOwnershipConfig) (cldf.ChangesetOutput, error) {
	plan, err := planTransfer(env, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	if cfg.MCMS == nil {
		for _, fwd := range plan.fwds {
			tx, err := fwd.contract.TransferOwnership(deployerOpts(plan.chain), plan.to)
			if err := confirm(plan.chain, tx, err, fmt.Sprintf("transfer ownership of %s forwarder %s", fwd.zone, fwd.address.StringLong())); err != nil {
				return cldf.ChangesetOutput{}, err
			}
			env.Logger.Infow("Proposed new forwarder owner; it must accept_ownership", "zone", fwd.zone, "forwarder", fwd.address.StringLong(), "to", plan.to.StringLong())
		}
		return cldf.ChangesetOutput{}, nil
	}

	enc := adapterbind.NewEncoder(plan.gov.adapter.address)
	var txs []mcmstypes.Transaction
	for _, fwd := range plan.fwds {
		tx, err := adapterTx(enc.TransferOwnership(fwd.address, plan.to))
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		txs = append(txs, tx)
	}
	return proposalOutput(env, cfg.ChainSelector, plan.gov.mcms, singleBatch(cfg.ChainSelector, txs),
		fmt.Sprintf("Transfer CRE forwarder ownership to %s", plan.to.StringLong()), *cfg.MCMS)
}

// AcceptForwarderOwnership completes a pending ownership transfer of the selected forwarders.
//
//   - MCMS: accepts as the adapter's MCMS owner account through an MCMS proposal (the handover to
//     MCMS). Each forwarder's pending owner must be that account.
//   - Direct (MCMS unset): the deployer accepts (e.g. after MCMS handed a forwarder back).
type AcceptForwarderOwnership struct{}

type acceptPlan struct {
	chain cldf_aptos.Chain
	fwds  []forwarder
	gov   governance // MCMS mode only
}

func planAccept(env cldf.Environment, cfg AcceptForwarderOwnershipConfig) (acceptPlan, error) {
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return acceptPlan{}, err
	}
	zones, err := zonesOrAll(cfg.Zones)
	if err != nil {
		return acceptPlan{}, err
	}
	plan := acceptPlan{chain: chain}

	var acceptor aptos.AccountAddress
	var acceptorDesc string
	if cfg.MCMS != nil {
		plan.gov, err = loadGovernance(env, chain, qualifierOrDefault(cfg.Qualifier))
		if err != nil {
			return acceptPlan{}, err
		}
		acceptor, acceptorDesc = plan.gov.adapter.owner, "the adapter's MCMS owner account"
	} else {
		acceptor, err = deployerAddress(chain)
		if err != nil {
			return acceptPlan{}, err
		}
		acceptorDesc = "the deployer"
	}

	var errs []error
	for _, zone := range zones {
		fwd, err := loadForwarder(env, chain, zone)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		pending, err := fwd.pendingOwner(chain.Client)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if pending != acceptor {
			errs = append(errs, fmt.Errorf("%s forwarder %s has pending owner %s, not %s (%s): the current owner must transfer_ownership to it first",
				zone, fwd.address.StringLong(), pending.StringLong(), acceptorDesc, acceptor.StringLong()))
			continue
		}
		plan.fwds = append(plan.fwds, fwd)
	}
	return plan, errors.Join(errs...)
}

func (AcceptForwarderOwnership) VerifyPreconditions(env cldf.Environment, cfg AcceptForwarderOwnershipConfig) error {
	_, err := planAccept(env, cfg)
	return err
}

func (AcceptForwarderOwnership) Apply(env cldf.Environment, cfg AcceptForwarderOwnershipConfig) (cldf.ChangesetOutput, error) {
	plan, err := planAccept(env, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}

	if cfg.MCMS == nil {
		for _, fwd := range plan.fwds {
			tx, err := fwd.contract.AcceptOwnership(deployerOpts(plan.chain))
			if err := confirm(plan.chain, tx, err, fmt.Sprintf("accept ownership of %s forwarder %s", fwd.zone, fwd.address.StringLong())); err != nil {
				return cldf.ChangesetOutput{}, err
			}
			env.Logger.Infow("Accepted forwarder ownership", "zone", fwd.zone, "forwarder", fwd.address.StringLong())
		}
		return cldf.ChangesetOutput{}, nil
	}

	enc := adapterbind.NewEncoder(plan.gov.adapter.address)
	var txs []mcmstypes.Transaction
	for _, fwd := range plan.fwds {
		tx, err := adapterTx(enc.AcceptOwnership(fwd.address))
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		txs = append(txs, tx)
	}
	return proposalOutput(env, cfg.ChainSelector, plan.gov.mcms, singleBatch(cfg.ChainSelector, txs),
		"MCMS accepts ownership of the CRE forwarders through the adapter", *cfg.MCMS)
}
