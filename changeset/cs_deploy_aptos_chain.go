package changeset

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip"
	mcmsbind "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms"
	module_mcms "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/mcms/mcms"
	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/mcms"
	aptosmcms "github.com/smartcontractkit/mcms/sdk/aptos"
	"github.com/smartcontractkit/mcms/types"
)

const AptosCCIPType deployment.ContractType = "AptosCCIP"

// CsDeployAptosChain deploys CCIP Package for Aptos chains
var CsDeployAptosChain deployment.ChangeSetV2[DeployAptosMCMSConfig] = CsDeployAptosMCMSImpl{}

type CsDeployAptosChainImp struct {
	onChainState map[uint64]AptosCCIPChainState
	env          deployment.Environment
	ab           *deployment.AddressBookMap
	proposals    []mcms.Proposal
}

func (cs *CsDeployAptosChainImp) VerifyPreconditions(env deployment.Environment, config DeployAptosChainConfig) error {
	// Validate configs
	if err := config.Validate(); err != nil {
		return fmt.Errorf("invalid DeployAptosChainConfig: %w", err)
	}

	// Validate env and prerequisite contracts
	state, err := LoadOnchainStateAptos(env)
	if err != nil {
		return fmt.Errorf("failed to load existing onchain state: %w", err)
	}
	failedEnvChains := []uint64{}
	failedPrereqChains := []uint64{}
	for chainSel := range config.ContractParamsPerChain {
		if _, ok := env.AptosChains[chainSel]; !ok {
			failedEnvChains = append(failedEnvChains, chainSel)
		}
		chainState, ok := state[chainSel]
		if !ok || chainState.AptosMCMSObjAddr == (aptos.AccountAddress{}) {
			failedPrereqChains = append(failedPrereqChains, chainSel)
		}
	}
	// If a chain is not in env it won't be in state, but these two checks are here to return clear errors
	if len(failedEnvChains) > 0 {
		return fmt.Errorf("env not found for chains: %v", failedEnvChains)
	}
	if len(failedPrereqChains) > 0 {
		return fmt.Errorf("MCMS contract not deployed for chains: %v", failedPrereqChains)
	}

	// Keep state for Apply
	cs.onChainState = state
	return nil
}

func (cs *CsDeployAptosChainImp) Apply(env deployment.Environment, config DeployAptosChainConfig) (deployment.ChangesetOutput, error) {
	cs.ab = deployment.NewMemoryAddressBook()

	// For each aptos chain in the config, deploy the CCIP package
	for chainSel := range config.ContractParamsPerChain {
		err := cs.getDeployAptosChainProposal(chainSel)
		if err != nil {
			env.Logger.Errorw("Failed to deploy CCIP contracts", "err", err, "newAddresses", cs.ab)
			return deployment.ChangesetOutput{AddressBook: cs.ab}, deployment.MaybeDataErr(err)
		}
		// TODO: Generate proposals to initialize contracts
	}

	return deployment.ChangesetOutput{
		AddressBook:   cs.ab,
		MCMSProposals: cs.proposals,
	}, nil
}

// getDeployAptosChainProposal generates deployment MCMS operations for the CCIP package
func (cs *CsDeployAptosChainImp) getDeployAptosChainProposal(chainSel uint64) error {
	chainState, ok := cs.onChainState[chainSel]
	if !ok {
		return fmt.Errorf("chain %d not found on state", chainSel)
	}
	aptosChain, ok := cs.env.AptosChains[chainSel]
	if !ok {
		return fmt.Errorf("chain %d not found in env", chainSel)
	}

	// Validate there's no package deployed
	if (chainState.AptosCCIPObjAddr != aptos.AccountAddress{}) {
		cs.env.Logger.Infow("CCIP Package already deployed", "addr", chainState.AptosCCIPObjAddr.String())
		return nil
	}

	// Compile, chunk and get CCIP deploy operations
	mcmsContract := mcmsbind.Bind(chainState.AptosMCMSObjAddr, aptosChain.Client)
	ccipObjectAddress, operations, err := cs.createDeployOperations(mcmsContract, chainSel)
	if err != nil {
		return fmt.Errorf("failed to compile and create deploy operations: %w", err)
	}
	// Save the address of the CCIP object
	typeAndVersion := deployment.NewTypeAndVersion(AptosCCIPType, deployment.Version1_0_0)
	cs.ab.Save(chainSel, ccipObjectAddress.String(), typeAndVersion)

	// Generate deploy proposal
	proposal, err := cs.generateDeployProposal(mcmsContract, chainSel, operations)
	if err != nil {
		return fmt.Errorf("failed to create deploy proposal: %w", err)
	}
	cs.proposals = append(cs.proposals, *proposal)

	return nil
}

func (cs *CsDeployAptosChainImp) createDeployOperations(mcmsContract mcmsbind.MCMS, chainSel uint64) (aptos.AccountAddress, []types.Operation, error) {
	var operations []types.Operation

	// Calculate addresses of the owner and the object
	ccipObjectAddress, err := mcmsContract.MCMSRegistry.GetNewCodeObjectAddress(nil, ccip.DefaultSeed)
	if err != nil {
		return ccipObjectAddress, operations, fmt.Errorf("failed to calculate CCIP object address: %w", err)
	}

	// Compile CCIP
	ccipPayload, err := ccip.Compile(ccipObjectAddress)
	if err != nil {
		return ccipObjectAddress, operations, fmt.Errorf("failed to compile CCIP: %w", err)
	}

	// Create chunks
	chunks, err := bind.CreateChunks(ccipPayload, bind.ChunkSizeInBytes)
	if err != nil {
		return ccipObjectAddress, operations, fmt.Errorf("failed to create chunks: %w", err)
	}

	// Stage chunks with mcms_deployer module and execute with the last one
	for i, chunk := range chunks {
		var (
			module   aptos.ModuleId
			function string
			args     [][]byte
			err      error
		)

		if i == len(chunks)-1 {
			// Last chunk stages the remaining data and executes
			module, function, _, args, err = mcmsContract.MCMSDeployer.EncodeStageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccip.DefaultSeed)
		} else {
			module, function, _, args, err = mcmsContract.MCMSDeployer.EncodeStageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)
		}
		if err != nil {
			return ccipObjectAddress, operations, fmt.Errorf("failed to encode chunk %d: %w", i, err)
		}
		additionalFields := aptosmcms.AdditionalFields{
			ModuleName: module.Name,
			Function:   function,
		}
		afBytes, err := json.Marshal(additionalFields)
		if err != nil {
			return ccipObjectAddress, operations, fmt.Errorf("failed to marshal additional fields: %w", err)
		}
		operations = append(operations, types.Operation{
			ChainSelector: types.ChainSelector(chainSel),
			Transaction: types.Transaction{
				To:               mcmsContract.Address.StringLong(),
				Data:             module_mcms.ArgsToData(args),
				AdditionalFields: afBytes,
			},
		})
	}

	return ccipObjectAddress, operations, nil
}

func (cs *CsDeployAptosChainImp) generateDeployProposal(mcmsContract mcmsbind.MCMS, chainSel uint64, operations []types.Operation) (*mcms.Proposal, error) {
	// Create MCMS inspector
	inspector := aptosmcms.NewInspector(cs.env.AptosChains[chainSel].Client)
	startingOpCount, err := inspector.GetOpCount(context.Background(), mcmsContract.Address.StringLong())

	// Create proposal builder
	validUntil := time.Now().Add(time.Hour * 24).Unix()
	proposalBuilder := mcms.NewProposalBuilder().
		SetVersion("v1").
		SetValidUntil(uint32(validUntil)).
		SetDescription("Test deploying CCIP via MCMS").
		SetOverridePreviousRoot(true).
		AddChainMetadata(
			types.ChainSelector(chainSel),
			types.ChainMetadata{
				StartingOpCount: startingOpCount,
				MCMAddress:      mcmsContract.Address.StringLong(),
			},
		)

	// Add operations and build
	for _, op := range operations {
		proposalBuilder.AddOperation(op)
	}
	proposal, err := proposalBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build proposal: %w", err)
	}

	return proposal, nil
}
