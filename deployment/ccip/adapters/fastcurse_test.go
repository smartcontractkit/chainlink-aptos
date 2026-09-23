package adapters

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	chainsel "github.com/smartcontractkit/chain-selectors"

	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf_datastore "github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/subjects"
)

func TestInitializeSetsCCIPAddress(t *testing.T) {
	selector := uint64(123)
	ccipAddrStr := "0x1"
	ccipAddr := aptos.AccountAddress{}
	require.NoError(t, ccipAddr.ParseStringRelaxed(ccipAddrStr))

	ds := cldf_datastore.NewMemoryDataStore()
	require.NoError(t, ds.Addresses().Add(cldf_datastore.AddressRef{
		ChainSelector: selector,
		Address:       ccipAddrStr,
		Type:          cldf_datastore.ContractType(shared.AptosCCIPType),
		Version:       semver.MustParse("1.0.0"),
	}))

	chain := cldf_aptos.Chain{Selector: selector}
	env := cldf.Environment{
		DataStore:   ds.Seal(),
		BlockChains: cldf_chain.NewBlockChainsFromSlice([]cldf_chain.BlockChain{chain}),
	}

	adapter := &CurseAdapter{}
	err := adapter.Initialize(env, selector)
	require.NoError(t, err)
	require.Equal(t, ccipAddr, adapter.CCIPAddress)
}

func TestSelectorSubjectConversions(t *testing.T) {
	adapter := &CurseAdapter{}
	selector := uint64(789)
	subject := adapter.SelectorToSubject(selector)
	outSelector, err := adapter.SubjectToSelector(subject)
	require.NoError(t, err)
	require.Equal(t, selector, outSelector)
	require.Equal(t, subjects.FamilyAwareSelectorToSubject(selector, chainsel.FamilyAptos), subject)
}
