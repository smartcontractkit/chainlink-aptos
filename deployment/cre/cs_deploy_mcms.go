package cre

import (
	"errors"
	"fmt"

	aptosmcms "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
)

var _ cldf.ChangeSetV2[DeployCREMCMSConfig] = DeployCREMCMS{}

// DeployCREMCMS deploys and configures a dedicated MCMS for the CRE forwarders, makes it propose
// ownership to itself, and returns the proposal that completes it (MCMS accepts ownership of
// itself and sets the timelock min delay). That proposal must execute before
// DeployForwarderAdapter, because mcms_deployer only publishes for a self-owned MCMS.
//
// It reuses the CCIP MCMS operations. The deploy operation takes no input, so it runs with an
// idempotency key per (qualifier, chain): otherwise the operations framework could replay a
// previous MCMS deploy report (e.g. CCIP's) and return that MCMS's address.
type DeployCREMCMS struct{}

func (DeployCREMCMS) VerifyPreconditions(env cldf.Environment, cfg DeployCREMCMSConfig) error {
	if _, err := aptosChain(env, cfg.ChainSelector); err != nil {
		return err
	}
	var errs []error
	for role, c := range map[string]mcmstypes.Config{"bypasser": cfg.MCMS.Bypasser, "canceller": cfg.MCMS.Canceller, "proposer": cfg.MCMS.Proposer} {
		if err := c.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid %s config: %w", role, err))
		}
	}
	if cfg.MCMS.TimelockMinDelay == nil || cfg.MCMS.TimelockMinDelay.Sign() < 0 || !cfg.MCMS.TimelockMinDelay.IsUint64() {
		errs = append(errs, errors.New("MCMS timelockMinDelay must be set to a non-negative value"))
	}
	errs = append(errs, shared.ValidatePlannedRefs(env, false, []shared.PlannedRef{{
		ChainSelector: cfg.ChainSelector,
		Type:          AptosMCMSType,
		Version:       Version1_0_0,
		Qualifier:     qualifierOrDefault(cfg.Qualifier),
		MultiInstance: true,
	}}))
	return errors.Join(errs...)
}

func (DeployCREMCMS) Apply(env cldf.Environment, cfg DeployCREMCMSConfig) (cldf.ChangesetOutput, error) {
	qualifier := qualifierOrDefault(cfg.Qualifier)
	chain, err := aptosChain(env, cfg.ChainSelector)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	deps := dependency.AptosDeps{AptosChain: chain}
	var reports []operations.Report[any, any]

	deployReport, err := operations.ExecuteOperation(env.OperationsBundle, operation.DeployMCMSOp, deps, operations.EmptyInput{},
		operations.WithIdempotencyKey[operations.EmptyInput, dependency.AptosDeps](fmt.Sprintf("cre-mcms/%s/%d", qualifier, cfg.ChainSelector)))
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("deploy MCMS: %w", err)
	}
	reports = append(reports, deployReport.ToGenericReport())
	mcmsAddr := deployReport.Output

	for _, role := range []struct {
		cfg  mcmstypes.Config
		role aptosmcms.TimelockRole
	}{
		{cfg.MCMS.Bypasser, aptosmcms.TimelockRoleBypasser},
		{cfg.MCMS.Canceller, aptosmcms.TimelockRoleCanceller},
		{cfg.MCMS.Proposer, aptosmcms.TimelockRoleProposer},
	} {
		r, err := operations.ExecuteOperation(env.OperationsBundle, operation.ConfigureMCMSOp, deps, operation.ConfigureMCMSInput{
			MCMSAddress: mcmsAddr,
			MCMSConfigs: role.cfg,
			MCMSRole:    role.role,
		})
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("configure MCMS %s role: %w", role.role.String(), err)
		}
		reports = append(reports, r.ToGenericReport())
	}

	toSelf, err := operations.ExecuteOperation(env.OperationsBundle, operation.TransferOwnershipToSelfOp, deps, mcmsAddr)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("MCMS transfer ownership to self: %w", err)
	}
	reports = append(reports, toSelf.ToGenericReport())

	accept, err := operations.ExecuteOperation(env.OperationsBundle, operation.AcceptOwnershipOp, deps, mcmsAddr)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("encode MCMS accept ownership: %w", err)
	}
	reports = append(reports, accept.ToGenericReport())

	minDelay, err := operations.ExecuteOperation(env.OperationsBundle, operation.SetMinDelayOP, deps, operation.TimelockMinDelayInput{
		MCMSAddress:      mcmsAddr,
		TimelockMinDelay: cfg.MCMS.TimelockMinDelay.Uint64(),
	})
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("encode MCMS set min delay: %w", err)
	}
	reports = append(reports, minDelay.ToGenericReport())

	ds := datastore.NewMemoryDataStore()
	if err := shared.RecordAddress(nil, ds, cfg.ChainSelector, mcmsAddr.StringLong(), cldf.NewTypeAndVersion(AptosMCMSType, Version1_0_0), qualifier); err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("record MCMS %s: %w", mcmsAddr.StringLong(), err)
	}
	env.Logger.Infow("Deployed CRE MCMS; execute its proposal (accept ownership + min delay) before publishing the adapter",
		"chainSelector", cfg.ChainSelector, "mcms", mcmsAddr.StringLong(), "qualifier", qualifier)

	out, err := proposalOutput(env, cfg.ChainSelector, mcmsAddr,
		singleBatch(cfg.ChainSelector, []mcmstypes.Transaction{accept.Output, minDelay.Output}),
		"CRE MCMS accepts ownership of itself and sets the timelock min delay", cfg.TimelockConfig)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	out.DataStore = ds
	out.Reports = reports
	return out, nil
}
