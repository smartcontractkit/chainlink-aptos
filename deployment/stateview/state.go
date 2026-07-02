package stateview

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	chainselectors "github.com/smartcontractkit/chain-selectors"

	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	aptosstate "github.com/smartcontractkit/chainlink-aptos/deployment/state"
)

// CCIPOnChainState holds Aptos-focused onchain state for Aptos deployment changesets.
type CCIPOnChainState struct {
	AptosChains map[uint64]aptosstate.CCIPChainState
}

// LoadOnchainState loads Aptos chain state from the environment address book.
func LoadOnchainState(env cldf.Environment) (CCIPOnChainState, error) {
	aptosChains, err := aptosstate.LoadOnchainState(env)
	if err != nil {
		return CCIPOnChainState{}, err
	}
	return CCIPOnChainState{AptosChains: aptosChains}, nil
}

func (c CCIPOnChainState) SupportedChains() map[uint64]struct{} {
	chains := make(map[uint64]struct{})
	for chain := range c.AptosChains {
		chains[chain] = struct{}{}
	}
	return chains
}

func (c CCIPOnChainState) GetOnRampAddressBytes(chainSelector uint64) ([]byte, error) {
	family, err := chainselectors.GetSelectorFamily(chainSelector)
	if err != nil {
		return nil, err
	}

	switch family {
	case chainselectors.FamilyAptos:
		ccipAddress := c.AptosChains[chainSelector].CCIPAddress
		if ccipAddress == (aptos.AccountAddress{}) {
			return nil, fmt.Errorf("no ccip address found in the state for Aptos chain %d", chainSelector)
		}
		return ccipAddress[:], nil
	default:
		return nil, fmt.Errorf("unsupported chain family for onramp lookup: %s", family)
	}
}
