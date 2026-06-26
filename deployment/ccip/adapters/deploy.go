package adapters

import (
	cldf_chain "github.com/smartcontractkit/chainlink-deployments-framework/chain"
	cldf_ops "github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-ccip/deployment/deploy"
	"github.com/smartcontractkit/chainlink-ccip/deployment/utils/sequences"
)

// AptosAdapter implements deploy.Deployer for Aptos chains.
// Aptos initial deploy stays on DeployAptosChain changeset; tooling deploy adapter
// methods other than SetOCR3Config are stubs until a later migration.
type AptosAdapter struct{}

var _ deploy.Deployer = (*AptosAdapter)(nil)

func (a *AptosAdapter) DeployChainContracts() *cldf_ops.Sequence[deploy.ContractDeploymentConfigPerChainWithAddress, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("DeployChainContracts not implemented for Aptos")
}

func (a *AptosAdapter) DeployMCMS() *cldf_ops.Sequence[deploy.MCMSDeploymentConfigPerChainWithAddress, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("DeployMCMS not implemented for Aptos")
}

func (a *AptosAdapter) FinalizeDeployMCMS() *cldf_ops.Sequence[deploy.MCMSDeploymentConfigPerChainWithAddress, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("FinalizeDeployMCMS not implemented for Aptos")
}

func (a *AptosAdapter) GrantAdminRoleToTimelock() *cldf_ops.Sequence[deploy.GrantAdminRoleToTimelockConfigPerChainWithSelector, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("GrantAdminRoleToTimelock not implemented for Aptos")
}

func (a *AptosAdapter) UpdateMCMSConfig() *cldf_ops.Sequence[deploy.UpdateMCMSConfigInputPerChainWithSelector, sequences.OnChainOutput, cldf_chain.BlockChains] {
	panic("UpdateMCMSConfig not implemented for Aptos")
}
