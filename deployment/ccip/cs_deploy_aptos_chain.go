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
	contracttypes "github.com/smartcontractkit/chainlink-aptos/deployment/types"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[config.DeployAptosChainConfig] = DeployAptosChain{}

// DeployAptosChain deploys Aptos chain packages and modules
type DeployAptosChain struct{}

func (cs DeployAptosChain) VerifyPreconditions(env cldf.Environment, config config.DeployAptosChainConfig) error {
	// Validate env and prerequisite contracts
	state, err := aptosstate.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	aptosChains := env.BlockChains.AptosChains()
	var errs []error
	var planned []shared.PlannedRef
	for chainSel := range config.ContractParamsPerChain {
		if err := config.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid config for Aptos chain %d: %w", chainSel, err))
			continue
		}
		if _, ok := aptosChains[chainSel]; !ok {
			errs = append(errs, fmt.Errorf("aptos chain %d not found in env", chainSel))
		}
		chainState, ok := state[chainSel]
		if !ok {
			errs = append(errs, fmt.Errorf("aptos chain %d not found in state", chainSel))
			continue
		}
		if chainState.MCMSAddress == (aptos.AccountAddress{}) {
			mcmsConfig := config.MCMSDeployConfigPerChain[chainSel]
			for _, cfg := range []mcmstypes.Config{mcmsConfig.Bypasser, mcmsConfig.Canceller, mcmsConfig.Proposer} {
				if err := cfg.Validate(); err != nil {
					errs = append(errs, fmt.Errorf("invalid mcms configs for Aptos chain %d: %w", chainSel, err))
				}
			}
			if mcmsConfig.TimelockMinDelay == nil {
				errs = append(errs, fmt.Errorf("invalid MCMS timelock min delay for Aptos chain %d: %s", chainSel, mcmsConfig.TimelockMinDelay))
			}
			// The MCMS sequence is a no-op when MCMS already exists, so only a fresh deploy
			// plans a ref. Several MCMS deployments coexist per chain, hence the purpose
			// qualifier.
			planned = append(planned, shared.PlannedRef{
				ChainSelector: chainSel,
				Type:          shared.AptosMCMSType,
				Version:       Version1_6_0,
				Qualifier:     shared.CLLCCIPQualifier,
				MultiInstance: true,
			})
		}
		if chainState.LinkTokenAddress == (aptos.AccountAddress{}) {
			planned = append(planned,
				shared.PlannedRef{
					ChainSelector: chainSel,
					Type:          shared.AptosManagedTokenType,
					Version:       Version1_6_0,
					Qualifier:     string(shared.LinkSymbol),
					MultiInstance: true,
				},
				shared.PlannedRef{
					ChainSelector: chainSel,
					Type:          contracttypes.LinkToken,
					Version:       Version1_6_0,
					Qualifier:     string(shared.LinkSymbol),
					MultiInstance: true,
				},
			)
		}
		// CCIP is deployed on every run and is a chain singleton, so an existing ref means
		// this run would deploy a second CCIP over the recorded one.
		planned = append(planned, shared.PlannedRef{
			ChainSelector: chainSel,
			Type:          shared.AptosCCIPType,
			Version:       Version1_6_0,
		})
	}
	// Validate that the datastore keys this changeset will write are free, before MCMS is
	// published with the deployer signer.
	errs = append(errs, shared.ValidatePlannedRefs(env, config.ReplaceExisting, planned))

	return errors.Join(errs...)
}

func (cs DeployAptosChain) Apply(env cldf.Environment, cfg config.DeployAptosChainConfig) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	ab := cldf.NewMemoryAddressBook()
	ds := datastore.NewMemoryDataStore()
	seqReports := make([]operations.Report[any, any], 0)
	proposals := make([]mcms.TimelockProposal, 0)
	// Qualifiers are declared at each RecordAddress site: the operating MCMS is purpose-scoped
	// (CLLCCIP), the LINK token is token-scoped (symbol), and the CCIP chain singleton is left
	// unqualified (empty).

	aptosChains := env.BlockChains.AptosChains()
	// Deploy CCIP on each Aptos chain in config
	for chainSel := range cfg.ContractParamsPerChain {
		var mcmsOperations []mcmstypes.BatchOperation
		aptosChain := aptosChains[chainSel]

		deps := dependency.AptosDeps{
			AB:               ab,
			AptosChain:       aptosChain,
			CCIPOnChainState: state,
		}

		// MCMS Deploy operations
		mcmsSeqReport, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployMCMSSequence, deps, cfg.MCMSDeployConfigPerChain[chainSel])
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		seqReports = append(seqReports, mcmsSeqReport.ExecutionReports...)
		mcmsOperations = append(mcmsOperations, mcmsSeqReport.Output.MCMSOperation)

		// The MCMS sequence returns the zero address when MCMS was already deployed on this
		// chain; recording that would write a zero-address ref and break the CCIP deploy below.
		mcmsAddress := mcmsSeqReport.Output.MCMSAddress
		if mcmsAddress == (aptos.AccountAddress{}) {
			mcmsAddress = state.AptosChains[chainSel].MCMSAddress
		} else {
			// Save MCMS address several MCMS deployments coexist per chain, hence the
			// purpose qualifier.
			mcmsTypeAndVersion := cldf.NewTypeAndVersion(shared.AptosMCMSType, Version1_6_0)
			if err := shared.RecordAddress(deps.AB, ds, chainSel, mcmsAddress.StringLong(), mcmsTypeAndVersion, shared.CLLCCIPQualifier); err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to save MCMS address %s for Aptos chain %d: %w", mcmsAddress.StringLong(), chainSel, err)
			}
		}

		// Deploy Link token if not already deployed
		linkTokenAddress := state.AptosChains[chainSel].LinkTokenAddress
		if linkTokenAddress == (aptos.AccountAddress{}) {
			// Deploy Link token
			deployTokenIn := seq.DeployTokenSeqInput{
				TokenParams: config.TokenParams{
					MaxSupply: nil,
					Name:      "ChainLink Token",
					Symbol:    "LINK",
					Decimals:  8,
					Icon:      "https://raw.githubusercontent.com/smartcontractkit/documentation/main/public/assets/icons/link.svg",
					Project:   "https://chain.link",
				},
				MCMSAddress: mcmsAddress,
			}
			linkSeqReport, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployAptosTokenSequence, deps, deployTokenIn)
			if err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to deploy Link token for Aptos chain %d: %w", chainSel, err)
			}
			seqReports = append(seqReports, linkSeqReport.ExecutionReports...)
			mcmsOperations = append(mcmsOperations, linkSeqReport.Output.MCMSOperations...)

			// Save token object address token-scoped, qualified by symbol
			tokenTypeAndVersion := cldf.NewTypeAndVersion(shared.AptosManagedTokenType, Version1_6_0)
			tokenTypeAndVersion.AddLabel(string(shared.LinkSymbol))
			if err := shared.RecordAddress(deps.AB, ds, chainSel, linkSeqReport.Output.TokenCodeObjAddress.StringLong(), tokenTypeAndVersion, string(shared.LinkSymbol)); err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to save Link token object address %s for Aptos chain %d: %w", linkSeqReport.Output.TokenCodeObjAddress.StringLong(), chainSel, err)
			}
			// Save Link token address token-scoped, qualified by symbol
			linkTypeAndVersion := cldf.NewTypeAndVersion(contracttypes.LinkToken, Version1_6_0)
			if err := shared.RecordAddress(deps.AB, ds, chainSel, linkSeqReport.Output.TokenAddress.StringLong(), linkTypeAndVersion, string(shared.LinkSymbol)); err != nil {
				return cldf.ChangesetOutput{}, fmt.Errorf("failed to save Link token address %s for Aptos chain %d: %w", linkSeqReport.Output.TokenAddress.StringLong(), chainSel, err)
			}
			linkTokenAddress = linkSeqReport.Output.TokenAddress

			// Add token to config
			params := cfg.ContractParamsPerChain[chainSel]
			params.FeeQuoterParams.FeeTokens = append(params.FeeQuoterParams.FeeTokens, linkTokenAddress)
			cfg.ContractParamsPerChain[chainSel] = params
		}

		// CCIP Deploy operations
		ccipSeqInput := seq.DeployCCIPSeqInput{
			MCMSAddress:      mcmsAddress,
			LinkTokenAddress: linkTokenAddress,
			CCIPConfig:       cfg.ContractParamsPerChain[chainSel],
		}
		ccipSeqReport, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployCCIPSequence, deps, ccipSeqInput)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to deploy CCIP for Aptos chain %d: %w", chainSel, err)
		}
		seqReports = append(seqReports, ccipSeqReport.ExecutionReports...)
		mcmsOperations = append(mcmsOperations, ccipSeqReport.Output.MCMSOperations...)

		// Save the address of the CCIP object a chain singleton, left unqualified
		ccipTypeAndVersion := cldf.NewTypeAndVersion(shared.AptosCCIPType, Version1_6_0)
		if err := shared.RecordAddress(deps.AB, ds, chainSel, ccipSeqReport.Output.CCIPAddress.StringLong(), ccipTypeAndVersion, shared.ChainSingletonQualifier); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to save CCIP address %s for Aptos chain %d: %w", ccipSeqReport.Output.CCIPAddress.StringLong(), chainSel, err)
		}

		// Generate MCMS proposals
		proposal, err := utils.GenerateProposal(
			env,
			mcmsAddress,
			chainSel,
			mcmsOperations,
			"Deploy Aptos MCMS and CCIP",
			cfg.MCMSTimelockConfigPerChain[chainSel],
		)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", chainSel, err)
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
