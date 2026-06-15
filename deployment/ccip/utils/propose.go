package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmslib "github.com/smartcontractkit/mcms"
	mcmschainwrappers "github.com/smartcontractkit/mcms/chainwrappers"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	"github.com/smartcontractkit/mcms/types"

	cldf_adapters "github.com/smartcontractkit/chainlink-deployments-framework/chain/mcms/adapters"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
)

const defaultValidUntil = 72 * time.Hour

type chainMetadata map[uint64]map[string]any

func (c *chainMetadata) set(chainSelector uint64, key string, value any) *chainMetadata {
	if _, exists := (*c)[chainSelector]; !exists {
		(*c)[chainSelector] = make(map[string]any)
	}
	(*c)[chainSelector][key] = value
	return c
}

// BuildProposalFromBatchesV2 builds a timelock MCMS proposal from batch operations.
func BuildProposalFromBatchesV2(
	e cldf.Environment,
	timelockAddressPerChain map[uint64]string,
	mcmsAddressPerChain map[uint64]string,
	inspectorPerChain map[uint64]mcmssdk.Inspector,
	batches []types.BatchOperation,
	description string,
	mcmsCfg cldfproposalutils.TimelockConfig,
) (*mcmslib.TimelockProposal, error) {
	if mcmsCfg.MCMSAction == "" {
		mcmsCfg.MCMSAction = types.TimelockActionSchedule
	}
	if len(batches) == 0 {
		return nil, errors.New("no operations in batch")
	}

	chains := mapset.NewSet[uint64]()
	for _, op := range batches {
		chains.Add(uint64(op.ChainSelector))
	}
	tlsPerChainID := make(map[types.ChainSelector]string)
	for chainID, tl := range timelockAddressPerChain {
		tlsPerChainID[types.ChainSelector(chainID)] = tl
	}
	mcmsMd, err := buildProposalMetadataV2(e, chains.ToSlice(), inspectorPerChain, mcmsAddressPerChain, mcmsCfg.MCMSAction, nil)
	if err != nil {
		return nil, err
	}

	proposalDuration := defaultValidUntil
	if mcmsCfg.ValidDuration != nil {
		proposalDuration = mcmsCfg.ValidDuration.Duration
	}
	validUntil := time.Now().Add(proposalDuration).Unix()

	builder := mcmslib.NewTimelockProposalBuilder()
	builder.
		SetVersion("v1").
		SetAction(mcmsCfg.MCMSAction).
		//nolint:gosec // G115
		SetValidUntil(uint32(validUntil)).
		SetDescription(description).
		SetDelay(types.NewDuration(mcmsCfg.MinDelay)).
		SetOverridePreviousRoot(mcmsCfg.OverrideRoot).
		SetChainMetadata(mcmsMd).
		SetTimelockAddresses(tlsPerChainID).
		SetOperations(batches)

	return builder.Build()
}

func buildProposalMetadataV2(
	env cldf.Environment,
	chainSelectors []uint64,
	inspectorPerChain map[uint64]mcmssdk.Inspector,
	mcmAddresses map[uint64]string,
	mcmsAction types.TimelockAction,
	additionalChainMetadata chainMetadata,
) (map[types.ChainSelector]types.ChainMetadata, error) {
	proposalChainMetadata := make(map[types.ChainSelector]types.ChainMetadata)

	if len(additionalChainMetadata) == 0 {
		additionalChainMetadata = make(chainMetadata)
	}

	for _, selector := range chainSelectors {
		mcmAddress, ok := mcmAddresses[selector]
		if !ok {
			return nil, fmt.Errorf("missing mcm address for chain %d", selector)
		}

		chainID := types.ChainSelector(selector)
		family, err := chain_selectors.GetSelectorFamily(selector)
		if err != nil {
			return nil, fmt.Errorf("failed to get family for chain %d: %w", selector, err)
		}

		switch family {
		case chain_selectors.FamilySolana:
			return nil, fmt.Errorf("solana MCMS proposals require chain state; use chainlink deployment proposalutils")
		case chain_selectors.FamilyAptos:
			role, err := cldfproposalutils.GetAptosRoleFromAction(mcmsAction)
			if err != nil {
				return nil, fmt.Errorf("failed to get role from action: %w", err)
			}
			additionalChainMetadata.set(selector, "role", role)
			proposalChainMetadata[chainID] = types.ChainMetadata{MCMAddress: mcmAddress}
		default:
			proposalChainMetadata[chainID] = types.ChainMetadata{MCMAddress: mcmAddress}
		}
	}

	if len(inspectorPerChain) == 0 {
		mcmsChains := cldf_adapters.Wrap(env.BlockChains)
		inspectors, err := mcmschainwrappers.BuildInspectors(&mcmsChains, proposalChainMetadata, mcmsAction)
		if err != nil {
			return nil, fmt.Errorf("failed to build inspectors: %w", err)
		}

		inspectorPerChain = make(map[uint64]mcmssdk.Inspector)
		for selector, inspector := range inspectors {
			inspectorPerChain[uint64(selector)] = inspector
		}
	}

	for selector, metadata := range proposalChainMetadata {
		inspector, ok := inspectorPerChain[uint64(selector)]
		if !ok {
			return nil, fmt.Errorf("failed to get inspector for chain %d", selector)
		}

		opCount, err := inspector.GetOpCount(env.GetContext(), metadata.MCMAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get op count for chain %d: %w", selector, err)
		}
		metadata.StartingOpCount = opCount

		if additionalMetadata, exists := additionalChainMetadata[uint64(selector)]; exists {
			marshalledAdditionalMetadata, err := json.Marshal(additionalMetadata)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal extra chain metadata for chain %d: %w", selector, err)
			}
			metadata.AdditionalFields = marshalledAdditionalMetadata
		}

		proposalChainMetadata[selector] = metadata
	}

	return proposalChainMetadata, nil
}
