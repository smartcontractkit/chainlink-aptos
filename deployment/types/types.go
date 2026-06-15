package types

import (
	"math/big"

	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
)

const LinkToken cldf.ContractType = "LinkToken"

// MCMSWithTimelockConfigV2 holds the configuration for an MCMS with timelock.
type MCMSWithTimelockConfigV2 struct {
	Canceller        mcmstypes.Config                  `json:"canceller"`
	Bypasser         mcmstypes.Config                  `json:"bypasser"`
	Proposer         mcmstypes.Config                  `json:"proposer"`
	TimelockMinDelay *big.Int                          `json:"timelockMinDelay"`
	Label            *string                           `json:"label"`
	GasBoostConfig   *cldfproposalutils.GasBoostConfig `json:"gasBoostConfig"`
	Qualifier        *string                           `json:"qualifier"`
}
