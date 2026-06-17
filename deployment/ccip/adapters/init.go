package adapters

import (
	chainsel "github.com/smartcontractkit/chain-selectors"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/fastcurse"
	"github.com/smartcontractkit/chainlink-ccip/deployment/lanes"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/changesets"

	aptosccip "github.com/smartcontractkit/chainlink-aptos/deployment/ccip"
)

func init() {
	v := &aptosccip.Version1_6_0

	curseRegistry := fastcurse.GetCurseRegistry()
	curseRegistry.RegisterNewCurse(fastcurse.CurseRegistryInput{
		CursingFamily:       chainsel.FamilyAptos,
		CursingVersion:      v,
		CurseAdapter:        NewCurseAdapter(),
		CurseSubjectAdapter: NewCurseAdapter(),
	})

	mcmsRegistry := changesets.GetRegistry()
	mcmsRegistry.RegisterMCMSReader(chainsel.FamilyAptos, &AptosCurseMCMSReader{})

	deploy.GetRegistry().RegisterDeployer(chainsel.FamilyAptos, v, &AptosAdapter{})
	lanes.GetLaneAdapterRegistry().RegisterLaneAdapter(chainsel.FamilyAptos, v, &AptosLaneAdapter{})
}
