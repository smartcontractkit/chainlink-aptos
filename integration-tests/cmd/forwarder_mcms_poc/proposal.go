package main

import (
	"encoding/json"
	"fmt"
	"time"

	mcmslib "github.com/smartcontractkit/mcms"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

// adapterCall is one call into forwarder_mcms_adapter::adapter::mcms_entrypoint.
// data is the concatenated BCS encoding of the function's args.
type adapterCall struct {
	function string
	data     []byte
}

// executeAdapterCalls builds a bypasser timelock proposal with the given adapter calls, signs it with
// the 1-of-1 MCMS signer, sets the root and executes each operation.
//
// On-chain path per op:
//
//	mcms::execute -> timelock_bypasser_execute_batch -> timelock_dispatch
//	  -> mcms_registry::start_dispatch + dispatchable_fungible_asset::derived_supply
//	  -> adapter::mcms_entrypoint -> dummy_forwarder::forwarder::<fn>(&adapter_owner_signer, ...)
func (e *env) executeAdapterCalls(description string, calls ...adapterCall) error {
	adapterAddr, err := e.addr("adapter", e.st.Adapter)
	if err != nil {
		return err
	}
	if e.st.MCMS == "" {
		return fmt.Errorf("mcms address not in state file; run deploy-mcms first")
	}

	inspector := aptossdk.NewInspector(e.client, aptossdk.TimelockRoleBypasser)
	startingOpCount, err := inspector.GetOpCount(e.ctx, e.st.MCMS)
	if err != nil {
		return fmt.Errorf("get op count: %w", err)
	}

	metadataFields, err := json.Marshal(aptossdk.AdditionalFieldsMetadata{Role: aptossdk.TimelockRoleBypasser})
	if err != nil {
		return err
	}

	bop := mcmstypes.BatchOperation{ChainSelector: e.chainSelector}
	for _, c := range calls {
		// The proposal validator rejects nil Data ("required"), but accepts an empty slice,
		// which is what no-arg functions like accept_ownership need.
		if c.data == nil {
			c.data = []byte{}
		}
		tx, err := aptossdk.NewTransaction(
			string(contracts.ForwarderMcmsAdapter),
			adapterModule,
			c.function,
			adapterAddr,
			c.data,
			"ForwarderMcmsAdapter",
			nil,
		)
		if err != nil {
			return err
		}
		bop.Transactions = append(bop.Transactions, tx)
	}

	timelockProposal, err := mcmslib.NewTimelockProposalBuilder().
		SetVersion("v1").
		SetValidUntil(uint32(time.Now().Add(time.Hour).Unix())).
		SetDescription(description).
		AddTimelockAddress(e.chainSelector, e.st.MCMS).
		AddChainMetadata(e.chainSelector, mcmstypes.ChainMetadata{
			StartingOpCount:  startingOpCount,
			MCMAddress:       e.st.MCMS,
			AdditionalFields: metadataFields,
		}).
		SetAction(mcmstypes.TimelockActionBypass).
		AddOperation(bop).
		Build()
	if err != nil {
		return fmt.Errorf("build proposal: %w", err)
	}

	proposal, _, err := timelockProposal.Convert(e.ctx, map[mcmstypes.ChainSelector]mcmssdk.TimelockConverter{
		e.chainSelector: aptossdk.NewTimelockConverter(),
	})
	if err != nil {
		return fmt.Errorf("convert timelock proposal: %w", err)
	}

	signable, err := mcmslib.NewSignable(&proposal, map[mcmstypes.ChainSelector]mcmssdk.Inspector{
		e.chainSelector: inspector,
	})
	if err != nil {
		return fmt.Errorf("create signable: %w", err)
	}
	if _, err := signable.SignAndAppend(mcmslib.NewPrivateKeySigner(e.mcmsSigner)); err != nil {
		return fmt.Errorf("sign proposal: %w", err)
	}
	quorumMet, err := signable.ValidateSignatures(e.ctx)
	if err != nil {
		return fmt.Errorf("validate signatures: %w", err)
	}
	if !quorumMet {
		return fmt.Errorf("quorum not met; is the bypasser config set to this signer?")
	}

	encoders, err := proposal.GetEncoders()
	if err != nil {
		return fmt.Errorf("get encoders: %w", err)
	}
	aptosEncoder := encoders[e.chainSelector].(*aptossdk.Encoder)
	executable, err := mcmslib.NewExecutable(&proposal, map[mcmstypes.ChainSelector]mcmssdk.Executor{
		e.chainSelector: aptossdk.NewExecutor(e.client, e.deployer, aptosEncoder, aptossdk.TimelockRoleBypasser),
	})
	if err != nil {
		return fmt.Errorf("create executable: %w", err)
	}

	res, err := executable.SetRoot(e.ctx, e.chainSelector)
	if err != nil {
		return fmt.Errorf("set root: %w", err)
	}
	if err := e.waitHash(res.Hash); err != nil {
		return fmt.Errorf("set root: %w", err)
	}
	fmt.Printf("MCMS set_root ok (tx %v)\n", res.Hash)

	for i := range proposal.Operations {
		res, err := executable.Execute(e.ctx, i)
		if err != nil {
			return fmt.Errorf("execute op %d: %w", i, err)
		}
		if err := e.waitHash(res.Hash); err != nil {
			return fmt.Errorf("execute op %d: %w", i, err)
		}
		fmt.Printf("MCMS execute op %d ok (tx %v)\n", i, res.Hash)
	}
	return nil
}

func (e *env) waitHash(hash string) error {
	data, err := e.client.WaitForTransaction(hash)
	if err != nil {
		return err
	}
	if !data.Success {
		return fmt.Errorf("tx %v failed: %v", hash, data.VmStatus)
	}
	return nil
}
