package ccip

import (
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/mcms"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	seq "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/sequence"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[config.DeployTokenFaucetInput] = DeployTokenFaucet{}

type DeployTokenFaucet struct{}

func (d DeployTokenFaucet) VerifyPreconditions(env cldf.Environment, cfg config.DeployTokenFaucetInput) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	if _, ok := state.SupportedChains()[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	if (cfg.TokenCodeObjectAddress == aptos.AccountAddress{}) {
		errs = append(errs, errors.New("managed token object address is empty"))
	}
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required"))
	}
	if (state.AptosChains[cfg.ChainSelector].MCMSAddress == aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("MCMS is not deployed on Aptos chain %d", cfg.ChainSelector))
	}

	return errors.Join(errs...)
}

func (d DeployTokenFaucet) Apply(env cldf.Environment, cfg config.DeployTokenFaucetInput) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	aptosChain := env.BlockChains.AptosChains()[cfg.ChainSelector]
	ab := cldf.NewMemoryAddressBook()

	deps := dependency.AptosDeps{
		AB:               ab,
		AptosChain:       aptosChain,
		CCIPOnChainState: state,
	}

	input := seq.DeployTokenFaucetSeqInput{
		MCMSAddress:         state.AptosChains[cfg.ChainSelector].MCMSAddress,
		TokenCodeObjAddress: cfg.TokenCodeObjectAddress,
	}
	report, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployTokenFaucetSequence, deps, input)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to execute DeployTokenFaucetSequence: %w", err)
	}

	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		report.Output,
		"Deploy Managed Token Faucet and grant mint rights to it",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}

	// This changeset records no addresses (the faucet address is carried in the proposal and
	// reports), so there is no datastore output.
	return cldf.ChangesetOutput{
		AddressBook:           ab,
		MCMSTimelockProposals: []mcms.TimelockProposal{*proposal},
		Reports:               []operations.Report[any, any]{report.ToGenericReport()},
	}, nil
}
