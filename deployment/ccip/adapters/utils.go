package adapters

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"

	datastore_utils "github.com/smartcontractkit/chainlink-ccip/deployment/utils/datastore"

	aptosccip "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	aptosstate "github.com/smartcontractkit/chainlink-aptos/deployment/state"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
)

func getCCIPAccountBytes(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return datastore_utils.FindAndFormatRef(ds, datastore.AddressRef{
		ChainSelector: chainSelector,
		Type:          datastore.ContractType(shared.AptosCCIPType),
		Version:       &aptosccip.Version1_6_0,
	}, chainSelector, accountAddressToBytes)
}

func getMCMSAccountBytes(ds datastore.DataStore, chainSelector uint64) ([]byte, error) {
	return datastore_utils.FindAndFormatRef(ds, datastore.AddressRef{
		ChainSelector: chainSelector,
		Type:          datastore.ContractType(shared.AptosMCMSType),
		Version:       &aptosccip.Version1_6_0,
	}, chainSelector, accountAddressToBytes)
}

func accountAddressToBytes(ref datastore.AddressRef) ([]byte, error) {
	var addr aptos.AccountAddress
	if err := addr.ParseStringRelaxed(ref.Address); err != nil {
		return nil, fmt.Errorf("parse aptos address %q: %w", ref.Address, err)
	}
	return addr[:], nil
}

func buildAptosDeps(chain cldf_aptos.Chain, chainSelector uint64, ccipBytes, mcmsBytes []byte) dependency.AptosDeps {
	var ccipAddr aptos.AccountAddress
	copy(ccipAddr[:], ccipBytes)

	deps := dependency.AptosDeps{
		AptosChain: chain,
		CCIPOnChainState: stateview.CCIPOnChainState{
			AptosChains: map[uint64]aptosstate.CCIPChainState{
				chainSelector: {CCIPAddress: ccipAddr},
			},
		},
	}

	if len(mcmsBytes) > 0 {
		var mcmsAddr aptos.AccountAddress
		copy(mcmsAddr[:], mcmsBytes)
		state := deps.CCIPOnChainState.AptosChains[chainSelector]
		state.MCMSAddress = mcmsAddr
		deps.CCIPOnChainState.AptosChains[chainSelector] = state
	}

	return deps
}
