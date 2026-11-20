package cre

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/smartcontractkit/mcms"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	cldfproposalutils "github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/mcms/proposalutils"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
)

// governance is the MCMS + adapter pair that owns forwarders in proposal mode.
type governance struct {
	mcms    aptos.AccountAddress
	adapter adapterInfo
}

func loadGovernance(env cldf.Environment, chain cldf_aptos.Chain, qualifier string) (governance, error) {
	mcmsAddr, err := mcmsAddress(env, chain.Selector, qualifier)
	if err != nil {
		return governance{}, err
	}
	adapter, err := loadAdapter(env, chain, qualifier)
	if err != nil {
		return governance{}, err
	}
	return governance{mcms: mcmsAddr, adapter: adapter}, nil
}

// adapterTx wraps one adapter call (from the adapter binding's Encoder) as an MCMS transaction
// targeting the adapter.
func adapterTx(module bind.ModuleInformation, function string, data []byte, err error) (mcmstypes.Transaction, error) {
	if err != nil {
		return mcmstypes.Transaction{}, fmt.Errorf("encode adapter %s: %w", function, err)
	}
	return utils.GenerateMCMSTx(module.Address, module, function, [][]byte{data})
}

// proposalOutput builds a single timelock proposal for MCMS on chain from one batch of
// transactions (executed atomically, in order).
func proposalOutput(env cldf.Environment, chainSelector uint64, mcmsAddr aptos.AccountAddress, batches []mcmstypes.BatchOperation, description string, cfg cldfproposalutils.TimelockConfig) (cldf.ChangesetOutput, error) {
	proposal, err := utils.GenerateProposal(env, mcmsAddr, chainSelector, batches, description, cfg)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("generate MCMS proposal for chain %d: %w", chainSelector, err)
	}
	return cldf.ChangesetOutput{MCMSTimelockProposals: []mcms.TimelockProposal{*proposal}}, nil
}

func singleBatch(chainSelector uint64, txs []mcmstypes.Transaction) []mcmstypes.BatchOperation {
	return []mcmstypes.BatchOperation{{
		ChainSelector: mcmstypes.ChainSelector(chainSelector),
		Transactions:  txs,
	}}
}

// confirm waits for a direct (deployer-signed) transaction.
func confirm(chain cldf_aptos.Chain, tx *api.PendingTransaction, err error, what string) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := chain.Confirm(tx.Hash); err != nil {
		return fmt.Errorf("%s (tx %s): %w", what, tx.Hash, err)
	}
	return nil
}

func deployerOpts(chain cldf_aptos.Chain) *bind.TransactOpts {
	return &bind.TransactOpts{Signer: chain.DeployerSigner}
}
