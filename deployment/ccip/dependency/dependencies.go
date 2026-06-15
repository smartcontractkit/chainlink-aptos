package dependency

import (
	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"
)

type AptosDeps struct {
	AB               *cldf.AddressBookMap
	AptosChain       cldf_aptos.Chain
	CCIPOnChainState stateview.CCIPOnChainState
}
