package adapters

import (
	"encoding/json"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosmcms "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	mcms_utils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/mcms"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	"github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/deployment/state"
)

// AptosMCMSReader implements changesets.MCMSReader for the Aptos family using the
// regular CCIP MCMS contract deployed by DeployAptosChain.
type AptosMCMSReader struct{}

func (r *AptosMCMSReader) GetChainMetadata(e deployment.Environment, chainSelector uint64, input mcms_utils.Input) (mcmstypes.ChainMetadata, error) {
	chain, ok := e.BlockChains.AptosChains()[chainSelector]
	if !ok {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("aptos chain with selector %d not found", chainSelector)
	}

	mcmsAddr, err := aptosMCMSAddress(e, chainSelector)
	if err != nil {
		return mcmstypes.ChainMetadata{}, err
	}

	role, err := cldfproposalutils.GetAptosRoleFromAction(input.TimelockAction)
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to get role from action: %w", err)
	}
	inspector := aptosmcms.NewInspector(chain.Client, role)

	opCount, err := inspector.GetOpCount(e.GetContext(), mcmsAddr.StringLong())
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to get opCount for MCMS at %s on chain %d: %w", mcmsAddr.StringLong(), chainSelector, err)
	}

	afBytes, err := json.Marshal(aptosmcms.AdditionalFieldsMetadata{Role: role})
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to marshal additional fields metadata: %w", err)
	}

	return mcmstypes.ChainMetadata{
		StartingOpCount:  opCount,
		MCMAddress:       mcmsAddr.StringLong(),
		AdditionalFields: afBytes,
	}, nil
}

func (r *AptosMCMSReader) GetTimelockRef(e deployment.Environment, chainSelector uint64, _ mcms_utils.Input) (datastore.AddressRef, error) {
	mcmsAddr, err := aptosMCMSAddress(e, chainSelector)
	if err != nil {
		return datastore.AddressRef{}, err
	}
	return datastore.AddressRef{
		Address:       mcmsAddr.StringLong(),
		ChainSelector: chainSelector,
	}, nil
}

func (r *AptosMCMSReader) GetMCMSRef(e deployment.Environment, chainSelector uint64, _ mcms_utils.Input) (datastore.AddressRef, error) {
	mcmsAddr, err := aptosMCMSAddress(e, chainSelector)
	if err != nil {
		return datastore.AddressRef{}, err
	}
	return datastore.AddressRef{
		Address:       mcmsAddr.StringLong(),
		ChainSelector: chainSelector,
	}, nil
}

func aptosMCMSAddress(e deployment.Environment, chainSelector uint64) (aptos.AccountAddress, error) {
	stateMap, err := state.LoadOnchainState(e)
	if err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("failed to load aptos onchain state: %w", err)
	}
	chainState, ok := stateMap[chainSelector]
	if !ok {
		return aptos.AccountAddress{}, fmt.Errorf("aptos chain %d not found in state", chainSelector)
	}
	if chainState.MCMSAddress == (aptos.AccountAddress{}) {
		return aptos.AccountAddress{}, fmt.Errorf("mcms address not set for aptos chain %d", chainSelector)
	}
	return chainState.MCMSAddress, nil
}

// AptosCurseMCMSReader implements changesets.MCMSReader for the Aptos CurseMCMS
// contract. It is not registered as the family reader; DeployCurseMCMS builds
// proposals directly. Kept for callers that need curse-MCMS metadata explicitly.
type AptosCurseMCMSReader struct{}

func (r *AptosCurseMCMSReader) GetChainMetadata(e deployment.Environment, chainSelector uint64, input mcms_utils.Input) (mcmstypes.ChainMetadata, error) {
	chain, ok := e.BlockChains.AptosChains()[chainSelector]
	if !ok {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("aptos chain with selector %d not found", chainSelector)
	}

	stateMap, err := state.LoadOnchainState(e)
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to load aptos onchain state: %w", err)
	}
	chainState, ok := stateMap[chainSelector]
	if !ok {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("aptos chain %d not found in state", chainSelector)
	}
	curseMCMSAddr := chainState.CurseMCMSAddress

	role, err := cldfproposalutils.GetAptosRoleFromAction(input.TimelockAction)
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to get role from action: %w", err)
	}
	inspector := aptosmcms.NewInspectorWithMCMSType(chain.Client, role, aptosmcms.MCMSTypeCurse)

	opCount, err := inspector.GetOpCount(e.GetContext(), curseMCMSAddr.StringLong())
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to get opCount for CurseMCMS at %s on chain %d: %w", curseMCMSAddr.StringLong(), chainSelector, err)
	}

	afBytes, err := json.Marshal(aptosmcms.AdditionalFieldsMetadata{
		Role:     role,
		MCMSType: aptosmcms.MCMSTypeCurse,
	})
	if err != nil {
		return mcmstypes.ChainMetadata{}, fmt.Errorf("failed to marshal additional fields metadata: %w", err)
	}

	return mcmstypes.ChainMetadata{
		StartingOpCount:  opCount,
		MCMAddress:       curseMCMSAddr.StringLong(),
		AdditionalFields: afBytes,
	}, nil
}

func (r *AptosCurseMCMSReader) GetTimelockRef(e deployment.Environment, chainSelector uint64, input mcms_utils.Input) (datastore.AddressRef, error) {
	stateMap, err := state.LoadOnchainState(e)
	if err != nil {
		return datastore.AddressRef{}, fmt.Errorf("failed to load aptos onchain state: %w", err)
	}
	chainState, ok := stateMap[chainSelector]
	if !ok {
		return datastore.AddressRef{}, fmt.Errorf("aptos chain %d not found in state", chainSelector)
	}
	return datastore.AddressRef{
		Address:       chainState.CurseMCMSAddress.StringLong(),
		ChainSelector: chainSelector,
	}, nil
}

func (r *AptosCurseMCMSReader) GetMCMSRef(e deployment.Environment, chainSelector uint64, input mcms_utils.Input) (datastore.AddressRef, error) {
	return r.GetTimelockRef(e, chainSelector, input)
}
