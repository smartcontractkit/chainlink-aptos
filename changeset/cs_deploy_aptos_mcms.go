package changeset

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	mcmsbind "github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	module_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
	"github.com/smartcontractkit/chainlink-aptos/utils"
	"github.com/smartcontractkit/chainlink/deployment"
	"github.com/smartcontractkit/mcms"
	aptosmcms "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"
)

const AptosMCMSType deployment.ContractType = "AptosManyChainMultisig"

const (
	ValidUntilHours         = 72
	MCMSProposalVersion     = "v1"
	MCMSProposalDescription = "Accept ownership of the contract to self"
)

var CsDeployAptosMCMS deployment.ChangeSetV2[DeployAptosMCMSConfig] = CsDeployAptosMCMSImpl{}

type deployAptosMCMSParams struct {
	env               deployment.Environment
	ab                *deployment.AddressBookMap
	chainSelector     uint64
	mcmsConfigs       mcmstypes.Config
	aptosOnChainState map[uint64]AptosCCIPChainState
	proposals         *[]mcms.Proposal
}

type CsDeployAptosMCMSImpl struct{}

func (c CsDeployAptosMCMSImpl) VerifyPreconditions(e deployment.Environment, config DeployAptosMCMSConfig) error {
	return nil
}

func (cs CsDeployAptosMCMSImpl) Apply(env deployment.Environment, c DeployAptosMCMSConfig) (deployment.ChangesetOutput, error) {
	state, err := LoadOnchainStateAptos(env)
	if err != nil {
		errRes := fmt.Errorf("failed to load existing onchain state: %w", err)
		env.Logger.Errorw(errRes.Error())
		return deployment.ChangesetOutput{}, errRes
	}

	newAddresses := deployment.NewMemoryAddressBook()
	proposals := []mcms.Proposal{}
	for chainSel, mcmsConfigs := range c.MCMSConfigPerChain {
		deployParams := deployAptosMCMSParams{
			env:               env,
			ab:                newAddresses,
			chainSelector:     chainSel,
			mcmsConfigs:       mcmsConfigs,
			aptosOnChainState: state,
			proposals:         &proposals,
		}
		err := deployMCMSContractsForAptosChain(&deployParams)
		if err != nil {
			errRes := fmt.Errorf("failed to deploy MCMS contracts for chain %d: %v", chainSel, err)
			env.Logger.Errorw(errRes.Error())
			return deployment.ChangesetOutput{AddressBook: newAddresses, MCMSProposals: proposals}, deployment.MaybeDataErr(errRes)
		}
	}

	return deployment.ChangesetOutput{
		AddressBook:   newAddresses,
		MCMSProposals: proposals,
	}, nil
}

func deployMCMSContractsForAptosChain(p *deployAptosMCMSParams) error {
	chainState, ok := p.aptosOnChainState[p.chainSelector]
	if !ok {
		return fmt.Errorf("chain %d not found on state", p.chainSelector)
	}
	aptosChain, ok := p.env.AptosChains[p.chainSelector]
	if !ok {
		return fmt.Errorf("chain %d not found in env", p.chainSelector)
	}

	// Check if MCMS package is already deployed
	if (chainState.AptosMCMSObjAddr != aptos.AccountAddress{}) {
		p.env.Logger.Infow("MCMS Package already deployed", "addr", chainState.AptosMCMSObjAddr.String())
		return nil
	}

	// Deploy MCMS
	mcmsSeed := mcmsbind.DefaultSeed + time.Now().String()
	addressMCMS, mcmsDeployTx, contractMCMS, err := mcmsbind.DeployToResourceAccount(aptosChain.DeployerSigner, aptosChain.Client, mcmsSeed)
	if err != nil {
		return fmt.Errorf("failed to deploy MCMS contract: %v", err)
	}
	if err := utils.ConfirmTx(aptosChain, mcmsDeployTx.Hash); err != nil {
		return fmt.Errorf("failed to confirm MCMS deployment transaction: %v", err)
	}

	typeAndVersion := deployment.NewTypeAndVersion(AptosMCMSType, deployment.Version1_0_0)
	p.ab.Save(p.chainSelector, addressMCMS.String(), typeAndVersion)

	// Configure MCMS
	configurer := aptosmcms.NewConfigurer(aptosChain.Client, aptosChain.DeployerSigner)
	setCfgTx, err := configurer.SetConfig(context.Background(), addressMCMS.StringLong(), &p.mcmsConfigs, false)
	if err != nil {
		return fmt.Errorf("failed to setConfig in MCMS contract: %v", err)
	}
	if err := utils.ConfirmTx(aptosChain, setCfgTx.Hash); err != nil {
		return fmt.Errorf("MCMS setConfig transaction failed: %v", err)
	}

	// Generate proposal to transfer ownership to self
	proposal, err := getMCMSProposal(aptosChain, addressMCMS, contractMCMS, p.chainSelector)
	if err != nil {
		return fmt.Errorf("failed to build proposal: %v", err)
	}
	*p.proposals = append(*p.proposals, *proposal)

	return nil
}

func getMCMSProposal(
	aptosChain deployment.AptosChain,
	addressMCMS aptos.AccountAddress,
	contractMCMS mcmsbind.MCMS,
	chainSelector uint64,
) (*mcms.Proposal, error) {
	opts := &bind.TransactOpts{Signer: aptosChain.DeployerSigner}
	tx, err := contractMCMS.MCMSAccount.TransferOwnershipToSelf(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to TransferOwnershipToSelf in MCMS contract: %v", err)
	}
	_, err = aptosChain.Client.WaitForTransaction(tx.Hash)
	if err != nil {
		return nil, fmt.Errorf("MCMS TransferOwnershipToSelf transaction failed: %v", err)
	}

	validUntil := time.Now().Add(time.Hour * ValidUntilHours).Unix()
	proposalBuilder := mcms.NewProposalBuilder().
		SetVersion(MCMSProposalVersion).
		SetValidUntil(uint32(validUntil)).
		SetDescription(MCMSProposalDescription).
		SetOverridePreviousRoot(true).
		AddChainMetadata(
			mcmstypes.ChainSelector(chainSelector),
			mcmstypes.ChainMetadata{
				StartingOpCount: 0,
				MCMAddress:      contractMCMS.Address.StringLong(),
			},
		)

	module, function, _, args, err := contractMCMS.MCMSAccount.EncodeAcceptOwnership()
	if err != nil {
		return nil, fmt.Errorf("failed to encode AcceptOwnership: %v", err)
	}
	additionalFields := aptosmcms.AdditionalFields{
		ModuleName: module.Name,
		Function:   function,
	}
	callOneAdditionalFields, err := json.Marshal(additionalFields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal additionalFields: %v", err)
	}
	proposalBuilder.AddOperation(mcmstypes.Operation{
		ChainSelector: mcmstypes.ChainSelector(chainSelector),
		Transaction: mcmstypes.Transaction{
			To:               addressMCMS.StringLong(),
			Data:             module_mcms.ArgsToData(args),
			AdditionalFields: callOneAdditionalFields,
		},
	})

	return proposalBuilder.Build()
}
