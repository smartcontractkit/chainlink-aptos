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
// data is the concatenated BCS encoding of the function's args; for every adapter function the
// first arg is the target forwarder address.
type adapterCall struct {
	function string
	data     []byte
}

// executeAdapterCalls runs the given adapter calls as one MCMS proposal (one op per call).
//
// On-chain path per op:
//
//	mcms::execute -> timelock_bypasser_execute_batch -> timelock_dispatch
//	  -> mcms_registry::start_dispatch + dispatchable_fungible_asset::derived_supply
//	  -> adapter::mcms_entrypoint -> <target forwarder>::<fn>(&adapter_owner_signer, ...)
func (e *env) executeAdapterCalls(description string, calls ...adapterCall) error {
	adapterAddr, err := e.addr("adapter", e.st.Adapter)
	if err != nil {
		return err
	}
	ops := make([]mcmstypes.Operation, 0, len(calls))
	for _, c := range calls {
		// The proposal validator rejects nil Data ("required"), but accepts an empty slice.
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
		ops = append(ops, mcmstypes.Operation{ChainSelector: e.chainSelector, Transaction: tx})
	}
	return e.executeProposal(description, ops)
}

// executeProposal builds a bypasser timelock proposal with one batch operation per op, signs it
// with the 1-of-1 MCMS signer, sets the root and executes every operation in order. Each op is
// its own batch (and so its own Aptos tx), which keeps staged code chunks under tx size limits.
func (e *env) executeProposal(description string, ops []mcmstypes.Operation) error {
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

	builder := mcmslib.NewTimelockProposalBuilder().
		SetVersion("v1").
		SetValidUntil(uint32(time.Now().Add(time.Hour).Unix())).
		SetDescription(description).
		// A failed op (e.g. mcms-bad-target) leaves the previous root with pending ops;
		// overriding lets the next proposal proceed. Fine for a PoC.
		SetOverridePreviousRoot(true).
		AddTimelockAddress(e.chainSelector, e.st.MCMS).
		AddChainMetadata(e.chainSelector, mcmstypes.ChainMetadata{
			StartingOpCount:  startingOpCount,
			MCMAddress:       e.st.MCMS,
			AdditionalFields: metadataFields,
		}).
		SetAction(mcmstypes.TimelockActionBypass)
	for _, op := range ops {
		if op.Transaction.Data == nil {
			op.Transaction.Data = []byte{}
		}
		builder = builder.AddOperation(mcmstypes.BatchOperation{
			ChainSelector: e.chainSelector,
			Transactions:  []mcmstypes.Transaction{op.Transaction},
		})
	}
	timelockProposal, err := builder.Build()
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
