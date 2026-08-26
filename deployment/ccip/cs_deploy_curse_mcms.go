package ccip

import (
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/mcms"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	seq "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/sequence"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	aptosstate "github.com/smartcontractkit/chainlink-aptos/deployment/state"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[config.DeployCurseMCMSConfig] = DeployCurseMCMS{}

// DeployCurseMCMS deploys and configures the CurseMCMS contract on Aptos chains.
type DeployCurseMCMS struct{}

func (cs DeployCurseMCMS) VerifyPreconditions(env cldf.Environment, cfg config.DeployCurseMCMSConfig) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	state, err := aptosstate.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	aptosChains := env.BlockChains.AptosChains()
	var errs []error
	var planned []shared.PlannedRef
	for chainSel := range cfg.CurseMCMSConfigPerChain {
		if _, ok := aptosChains[chainSel]; !ok {
			errs = append(errs, fmt.Errorf("aptos chain %d not found in env", chainSel))
			continue
		}
		chainState, ok := state[chainSel]
		if !ok {
			errs = append(errs, fmt.Errorf("aptos chain %d not found in state", chainSel))
			continue
		}
		if chainState.MCMSAddress == (aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("MCMS not deployed for Aptos chain %d", chainSel))
		}
		if chainState.CCIPAddress == (aptos.AccountAddress{}) {
			errs = append(errs, fmt.Errorf("CCIP not deployed for Aptos chain %d", chainSel))
		}
		// The sequence is a no-op when CurseMCMS already exists, so only a fresh deploy plans
		// a ref. AptosCurseMCMS is a chain singleton: its type already encodes the purpose.
		if chainState.CurseMCMSAddress == (aptos.AccountAddress{}) {
			planned = append(planned, shared.PlannedRef{
				ChainSelector: chainSel,
				Type:          shared.AptosCurseMCMSType,
				Version:       Version1_6_0,
			})
		}
	}
	// Validate that the datastore keys this changeset will write are free, before CurseMCMS is
	// published with the deployer signer.
	errs = append(errs, shared.ValidatePlannedRefs(env, cfg.ReplaceExisting, planned))

	return errors.Join(errs...)
}

func (cs DeployCurseMCMS) Apply(env cldf.Environment, cfg config.DeployCurseMCMSConfig) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load onchain state: %w", err)
	}

	ab := cldf.NewMemoryAddressBook()
	ds := datastore.NewMemoryDataStore()
	seqReports := make([]operations.Report[any, any], 0)
	proposals := make([]mcms.TimelockProposal, 0)

	aptosChains := env.BlockChains.AptosChains()
	for chainSel, curseMCMSConfig := range cfg.CurseMCMSConfigPerChain {
		aptosChain := aptosChains[chainSel]
		chainState := state.AptosChains[chainSel]

		deps := dependency.AptosDeps{
			AB:               ab,
			AptosChain:       aptosChain,
			CCIPOnChainState: state,
		}

		seqInput := seq.DeployCurseMCMSSeqInput{
			MCMSAddress: chainState.MCMSAddress,
			CCIPAddress: chainState.CCIPAddress,
			CurseMCMS:   curseMCMSConfig,
		}

		curseMCMSSeqReport, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployCurseMCMSSequence, deps, seqInput)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to deploy CurseMCMS for Aptos chain %d: %w", chainSel, err)
		}
		seqReports = append(seqReports, curseMCMSSeqReport.ExecutionReports...)

		// Skip address saving and proposal generation when sequence was a no-op (already deployed).
		if curseMCMSSeqReport.Output.CurseMCMSAddress == (aptos.AccountAddress{}) {
			continue
		}

		// AptosCurseMCMS is a chain singleton: its type already encodes the curse purpose.
		typeAndVersion := cldf.NewTypeAndVersion(shared.AptosCurseMCMSType, Version1_6_0)
		if err := shared.RecordAddress(ab, ds, chainSel, curseMCMSSeqReport.Output.CurseMCMSAddress.StringLong(), typeAndVersion, shared.ChainSingletonQualifier); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to save CurseMCMS address for Aptos chain %d: %w", chainSel, err)
		}

		// Generate a CurseMCMS proposal for self-governance operations (AcceptOwnership + SetMinDelay).
		proposal, err := utils.GenerateCurseMCMSProposal(
			env,
			curseMCMSSeqReport.Output.CurseMCMSAddress,
			chainSel,
			[]mcmstypes.BatchOperation{curseMCMSSeqReport.Output.CurseMCMSOperation},
			"CurseMCMS accept ownership and set timelock min delay",
			cfg.MCMSTimelockConfigPerChain[chainSel],
		)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate CurseMCMS proposal for Aptos chain %d: %w", chainSel, err)
		}
		proposals = append(proposals, *proposal)
	}

	return cldf.ChangesetOutput{
		AddressBook:           ab,
		DataStore:             ds,
		MCMSTimelockProposals: proposals,
		Reports:               seqReports,
	}, nil
}
