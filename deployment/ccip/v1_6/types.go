package v1_6

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-ccip/chains/evm/gobindings/generated/v1_6_3/fee_quoter"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
)

// ConnectionConfig defines how a chain should connect with other chains.
type ConnectionConfig struct {
	RMNVerificationDisabled bool `json:"rmnVerificationDisabled"`
	AllowListEnabled        bool `json:"allowListEnabled"`
}

// ChainDefinition defines how a chain should be configured on both remote chains and itself.
type ChainDefinition struct {
	ConnectionConfig         `json:"connectionConfig"`
	Selector                 uint64                                    `json:"selector"`
	GasPrice                 *big.Int                                  `json:"gasPrice"`
	TokenPrices              map[common.Address]*big.Int               `json:"tokenPrices"`
	FeeQuoterDestChainConfig fee_quoter.FeeQuoterDestChainConfig       `json:"feeQuoterDestChainConfig"`
}

type OnRampDestinationUpdate struct {
	IsEnabled        bool
	TestRouter       bool
	AllowListEnabled bool
}

type UpdateOnRampDestsConfig struct {
	UpdatesByChain map[uint64]map[uint64]OnRampDestinationUpdate
	MCMS           *cldfproposalutils.TimelockConfig
}

type OffRampSourceUpdate struct {
	IsEnabled                 bool
	TestRouter                bool
	IsRMNVerificationDisabled bool
}

type UpdateOffRampSourcesConfig struct {
	UpdatesByChain map[uint64]map[uint64]OffRampSourceUpdate
	MCMS           *cldfproposalutils.TimelockConfig
	SkipOwnershipCheck bool
}

type RouterUpdates struct {
	OffRampUpdates map[uint64]bool
	OnRampUpdates  map[uint64]bool
}

type UpdateRouterRampsConfig struct {
	TestRouter         bool
	UpdatesByChain     map[uint64]RouterUpdates
	MCMS               *cldfproposalutils.TimelockConfig
	SkipOwnershipCheck bool
}

type UpdateFeeQuoterDestsConfig struct {
	UpdatesByChain map[uint64]map[uint64]fee_quoter.FeeQuoterDestChainConfig
	MCMS           *cldfproposalutils.TimelockConfig
}

type FeeQuoterPriceUpdatePerSource struct {
	TokenPrices map[common.Address]*big.Int
	GasPrices   map[uint64]*big.Int
}

type UpdateFeeQuoterPricesConfig struct {
	PricesByChain map[uint64]FeeQuoterPriceUpdatePerSource
	MCMS          *cldfproposalutils.TimelockConfig
}

type UpdateBidirectionalLanesChangesetConfigs struct {
	UpdateFeeQuoterDestsConfig  UpdateFeeQuoterDestsConfig
	UpdateFeeQuoterPricesConfig UpdateFeeQuoterPricesConfig
	UpdateOnRampDestsConfig     UpdateOnRampDestsConfig
	UpdateOffRampSourcesConfig  UpdateOffRampSourcesConfig
	UpdateRouterRampsConfig     UpdateRouterRampsConfig
}
