package config

import (
	"errors"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"

	fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"
)

type AddTokenPoolConfig struct {
	// DeployAptosTokenConfig
	ChainSelector                       uint64
	TokenAddress                        aptos.AccountAddress // if empty, token will be deployed
	TokenCodeObjAddress                 aptos.AccountAddress // if empty, token will be deployed
	TokenPoolAddress                    aptos.AccountAddress // if empty, token pool will be deployed
	PoolType                            cldf.ContractType
	TokenTransferFeeByRemoteChainConfig map[uint64]fee_quoter.TokenTransferFeeConfig
	EVMRemoteConfigs                    map[uint64]EVMRemoteConfig
	TokenParams                         TokenParams
	MCMSConfig                          *cldfproposalutils.TimelockConfig
	TokenMint                           *TokenMint
	// ReplaceExisting allows this changeset to take datastore keys that are already
	// recorded, as an intentional redeploy of this token or pool does. Without it, an
	// occupied key is an error raised before anything is deployed.
	ReplaceExisting bool
}

// Qualifier returns the datastore qualifier applied to every address this changeset
// records. Token-scoped types are qualified by token symbol, so the symbol is required
// even when the token already exists: pool refs are keyed by
// (chain, PoolType, version, qualifier) with the address excluded, and an empty qualifier
// would collide between two pools of the same type on one chain. The symbol is normalised
// to the convention's canonical form so Aptos rows key identically to other families'.
func (c AddTokenPoolConfig) Qualifier() shared.TokenSymbol {
	return shared.TokenSymbol(shared.TokenQualifier(c.TokenParams.Symbol.String()))
}

type EVMRemoteConfig struct {
	TokenAddress common.Address
	// TODO: EVM has a way of picking up Pool by token address and type, use this instead of passing PoolAddress
	TokenPoolAddress common.Address
	RateLimiterConfig
}

func (erc EVMRemoteConfig) Validate() error {
	if erc.TokenAddress == (common.Address{}) {
		return errors.New("TokenAddress cannot be empty")
	}
	if erc.TokenPoolAddress == (common.Address{}) {
		return errors.New("TokenPoolAddress cannot be empty")
	}

	return nil
}

type RateLimiterConfig struct {
	RemoteChainSelector uint64
	OutboundIsEnabled   bool
	OutboundCapacity    uint64
	OutboundRate        uint64
	InboundIsEnabled    bool
	InboundCapacity     uint64
	InboundRate         uint64
}

// ########################
// # Token Pool Ownership #
// ########################

type TokenPoolTransfer struct {
	TokenPoolAddress aptos.AccountAddress
	To               aptos.AccountAddress
	TokenPoolType    cldf.ContractType
}

type TransferTokenPoolOwnershipInput struct {
	ChainSelector uint64
	Transfers     []TokenPoolTransfer
	MCMSConfig    *cldfproposalutils.TimelockConfig
}

type TokenPoolAccept struct {
	TokenPoolAddress aptos.AccountAddress
	TokenPoolType    cldf.ContractType
}

type AcceptTokenPoolOwnershipInput struct {
	ChainSelector uint64
	Accepts       []TokenPoolAccept
	MCMSConfig    *cldfproposalutils.TimelockConfig
}

type ExecuteTokenPoolOwnershipTransferInput struct {
	ChainSelector uint64
	Transfers     []TokenPoolTransfer
	MCMSConfig    *cldfproposalutils.TimelockConfig
}
