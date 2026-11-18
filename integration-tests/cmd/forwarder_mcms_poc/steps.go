package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

const (
	forwarderModule = "forwarder"
	adapterModule   = "adapter"
)

// fwdTarget is one of the two dummy forwarders (mirrors platform / platform_secondary).
type fwdTarget struct {
	name      string            // "primary" | "secondary"
	pkg       contracts.Package // package name == its named address
	ownerAddr string            // named address of its initial owner
	addr      *string           // pointer into state
}

func (e *env) allTargets() []fwdTarget {
	return []fwdTarget{
		{name: "primary", pkg: contracts.DummyForwarder, ownerAddr: "owner", addr: &e.st.Forwarder},
		{name: "secondary", pkg: contracts.DummyForwarderSecondary, ownerAddr: "owner_secondary", addr: &e.st.ForwarderSecondary},
	}
}

// targets returns the forwarders selected with --target.
func (e *env) targets() ([]fwdTarget, error) {
	all := e.allTargets()
	switch e.flags.target {
	case "", "both":
		return all, nil
	case "primary":
		return all[:1], nil
	case "secondary":
		return all[1:], nil
	}
	return nil, fmt.Errorf("unknown --target %q (primary|secondary|both)", e.flags.target)
}

func (e *env) opts() *bind.TransactOpts {
	return &bind.TransactOpts{Signer: e.deployer}
}

func (e *env) forwarder(t fwdTarget) (*bind.BoundContract, aptos.AccountAddress, error) {
	a, err := e.addr(t.name+" forwarder", *t.addr)
	if err != nil {
		return nil, a, err
	}
	return bind.NewBoundContract(a, string(t.pkg), forwarderModule, e.client), a, nil
}

// ===== step: deploy-forwarder =====

func (e *env) deployForwarders() error {
	for _, t := range e.allTargets() {
		fmt.Printf("\n== deploy %s (%s forwarder) ==\n", t.pkg, t.name)
		addr, tx, err := bind.DeployPackageToObject(e.deployer, e.client, t.pkg,
			map[string]aptos.AccountAddress{t.ownerAddr: e.deployer.AccountAddress()},
			aptos.MaxGasAmount(e.flags.deployMaxGas),
		)
		if _, err := e.wait(err, tx); err != nil {
			return fmt.Errorf("deploy %s: %w", t.pkg, err)
		}
		*t.addr = addr.StringLong()
		fmt.Printf("%s forwarder deployed at %v (tx %v), owner = deployer\n", t.name, *t.addr, tx.Hash)
		if err := e.saveState(); err != nil {
			return err
		}
	}
	return nil
}

// ===== step: set-value (direct) =====

func (e *env) setValueDirect(t fwdTarget, n uint64) error {
	fmt.Printf("\n== deployer calls %s forwarder::set_value(%d) directly ==\n", t.name, n)
	fwd, _, err := e.forwarder(t)
	if err != nil {
		return err
	}
	module, fn, typeTags, args, err := fwd.Encode("set_value", nil, []string{"u64"}, []any{n})
	if err != nil {
		return err
	}
	tx, err := fwd.Transact(e.opts(), module, fn, typeTags, args)
	if _, err := e.wait(err, tx); err != nil {
		return err
	}
	fmt.Printf("set_value(%d) ok (tx %v)\n", n, tx.Hash)
	return e.printForwarder(t)
}

func (e *env) setValueDirectAll(n uint64) error {
	ts, err := e.targets()
	if err != nil {
		return err
	}
	for _, t := range ts {
		if err := e.setValueDirect(t, n); err != nil {
			return err
		}
	}
	return nil
}

// ===== status =====

func (e *env) view(c *bind.BoundContract, fn string, out any) error {
	module, f, typeTags, args, err := c.Encode(fn, nil, nil, nil)
	if err != nil {
		return err
	}
	res, err := c.Call(nil, module, f, typeTags, args)
	if err != nil {
		return fmt.Errorf("view %s: %w", fn, err)
	}
	return codec.DecodeAptosJsonArray(res, out)
}

func (e *env) forwarderState(t fwdTarget) (value uint64, owner, pending aptos.AccountAddress, err error) {
	fwd, _, err := e.forwarder(t)
	if err != nil {
		return
	}
	if err = e.view(fwd, "get_value", &value); err != nil {
		return
	}
	if err = e.view(fwd, "get_owner", &owner); err != nil {
		return
	}
	err = e.view(fwd, "get_pending_owner", &pending)
	return
}

func (e *env) printForwarder(t fwdTarget) error {
	value, owner, pending, err := e.forwarderState(t)
	if err != nil {
		return err
	}
	fmt.Printf("%-9s forwarder: value=%d owner=%v%s pending_owner=%v\n", t.name, value, owner.StringLong(), e.label(owner), pending.StringLong())
	return nil
}

// objectOwner reads 0x1::object::ObjectCore.owner of an object (for code objects: upgrade authority).
func (e *env) objectOwner(obj aptos.AccountAddress) (aptos.AccountAddress, error) {
	var owner aptos.AccountAddress
	res, err := e.client.AccountResource(obj, "0x1::object::ObjectCore")
	if err != nil {
		return owner, err
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return owner, fmt.Errorf("unexpected ObjectCore resource: %v", res)
	}
	s, ok := data["owner"].(string)
	if !ok {
		return owner, fmt.Errorf("unexpected ObjectCore owner: %v", data["owner"])
	}
	err = owner.ParseStringRelaxed(s)
	return owner, err
}

func (e *env) label(a aptos.AccountAddress) string {
	switch a.StringLong() {
	case e.deployer.Address.StringLong():
		return " (deployer)"
	case e.st.AdapterOwner:
		return " (adapter's MCMS owner account)"
	}
	return ""
}

func (e *env) printStatus() error {
	fmt.Println("\n== status ==")
	fmt.Printf("primary forwarder:   %v\n", e.st.Forwarder)
	fmt.Printf("secondary forwarder: %v\n", e.st.ForwarderSecondary)
	fmt.Printf("mcms:                %v\n", e.st.MCMS)
	fmt.Printf("adapter:             %v (seed %q)\n", e.st.Adapter, e.st.AdapterSeed)
	fmt.Printf("adapter MCMS owner:  %v\n", e.st.AdapterOwner)
	for _, t := range e.allTargets() {
		if *t.addr == "" {
			continue
		}
		if err := e.printForwarder(t); err != nil {
			return err
		}
	}
	if e.st.Adapter != "" && e.st.MCMS != "" {
		adapterAddr, err := e.addr("adapter", e.st.Adapter)
		if err != nil {
			return err
		}
		mcmsAddr, err := e.addr("mcms", e.st.MCMS)
		if err != nil {
			return err
		}
		codeOwner, err := e.objectOwner(adapterAddr)
		if err != nil {
			return fmt.Errorf("read adapter code object owner: %w", err)
		}
		owned, err := mcms.Bind(mcmsAddr, e.client).MCMSRegistry().IsOwnedCodeObject(nil, adapterAddr)
		if err != nil {
			return fmt.Errorf("is_owned_code_object: %w", err)
		}
		fmt.Printf("adapter code object: owner=%v%s mcms_registry::is_owned_code_object=%v\n", codeOwner.StringLong(), e.label(codeOwner), owned)
	}
	return nil
}

// ===== step: deploy-mcms =====

func (e *env) deployMCMS() error {
	fmt.Println("\n== deploy MCMS ==")
	// unique seed so the step can be re-run
	seed := mcms.DefaultSeed + time.Now().UTC().Format("20060102150405")
	addr, tx, err := bind.DeployPackageToResourceAccount(e.deployer, e.client, contracts.MCMS, seed,
		map[string]aptos.AccountAddress{"mcms_owner": e.deployer.AccountAddress()},
		aptos.MaxGasAmount(e.flags.deployMaxGas),
	)
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("deploy mcms: %w", err)
	}
	e.st.MCMS = addr.StringLong()
	fmt.Printf("MCMS deployed at %v (tx %v), MCMS owner = deployer\n", e.st.MCMS, tx.Hash)
	if err := e.saveState(); err != nil {
		return err
	}

	// 1-of-1 bypasser config. MCMS signers are EVM addresses (secp256k1); the deployer's ed25519
	// key only pays for and submits transactions.
	signer := ethcrypto.PubkeyToAddress(e.mcmsSigner.PublicKey)
	cfg := &mcmstypes.Config{Quorum: 1, Signers: []common.Address{signer}}
	configurer := aptossdk.NewConfigurer(e.client, e.deployer, aptossdk.TimelockRoleBypasser)
	res, err := configurer.SetConfig(e.ctx, e.st.MCMS, cfg, false)
	if err != nil {
		return fmt.Errorf("set bypasser config: %w", err)
	}
	if err := e.waitHash(res.Hash); err != nil {
		return fmt.Errorf("set bypasser config: %w", err)
	}
	fmt.Printf("bypasser role configured as 1-of-1 with signer %v (tx %v)\n", signer.Hex(), res.Hash)
	return nil
}

// ===== step: mcms-own-self =====

// mcmsOwnSelf makes MCMS its own owner (mcms_account owner == @mcms). Required before MCMS can
// publish code: timelock_dispatch calls mcms_deployer with the @mcms signer, and mcms_deployer
// asserts that caller is the mcms_account owner. Two steps, like the forwarders' ownership:
// the current owner (deployer) proposes @mcms, then an MCMS proposal accepts.
// After this, every MCMS admin action (set_config, deploys, registry ops) needs a proposal.
func (e *env) mcmsOwnSelf() error {
	fmt.Println("\n== MCMS takes ownership of itself ==")
	mcmsAddr, err := e.addr("mcms", e.st.MCMS)
	if err != nil {
		return err
	}
	account := mcms.Bind(mcmsAddr, e.client).MCMSAccount()
	selfOwned, err := account.IsSelfOwned(nil)
	if err != nil {
		return fmt.Errorf("is_self_owned: %w", err)
	}
	if selfOwned {
		fmt.Println("MCMS is already self-owned")
		return nil
	}

	tx, err := account.TransferOwnershipToSelf(e.opts())
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("mcms_account::transfer_ownership_to_self: %w", err)
	}
	fmt.Printf("deployer called mcms_account::transfer_ownership_to_self (tx %v)\n", tx.Hash)

	moduleInfo, function, _, args, err := account.Encoder().AcceptOwnership()
	if err != nil {
		return err
	}
	mcmsTx, err := utils.GenerateMCMSTx(mcmsAddr, moduleInfo, function, args)
	if err != nil {
		return err
	}
	if err := e.executeProposal("MCMS accepts ownership of itself", []mcmstypes.Operation{
		{ChainSelector: e.chainSelector, Transaction: mcmsTx},
	}); err != nil {
		return fmt.Errorf("accept self-ownership: %w", err)
	}

	owner, err := account.Owner(nil)
	if err != nil {
		return err
	}
	if owner != mcmsAddr {
		return fmt.Errorf("mcms_account owner is %v, expected %v", owner.StringLong(), mcmsAddr.StringLong())
	}
	fmt.Println("✅ MCMS is now self-owned; the deployer has no MCMS admin rights left")
	return nil
}

// ===== step: deploy-adapter (published by MCMS) =====

func (e *env) deployAdapter() error {
	fmt.Println("\n== MCMS publishes forwarder_mcms_adapter (via mcms_deployer) ==")
	mcmsAddr, err := e.addr("mcms", e.st.MCMS)
	if err != nil {
		return err
	}
	fwdAddr, err := e.addr("primary forwarder", e.st.Forwarder)
	if err != nil {
		return err
	}
	// MCMS can only publish via a proposal once it owns itself (mcms_deployer checks the owner).
	if err := e.mcmsOwnSelf(); err != nil {
		return err
	}
	fwd2Addr, err := e.addr("secondary forwarder", e.st.ForwarderSecondary)
	if err != nil {
		return err
	}
	mcmsContract := mcms.Bind(mcmsAddr, e.client)
	registry := mcmsContract.MCMSRegistry()

	// A seed can only be used once (mcms_registry creates one owner account per seed).
	seed := e.flags.adapterSeed
	if seed == "" {
		seed = fmt.Sprintf("forwarder_mcms_adapter_%d", time.Now().Unix())
	}

	// Both addresses are deterministic, so we can compile against the adapter address before it exists.
	adapterAddr, err := registry.GetNewCodeObjectAddress(nil, []byte(seed))
	if err != nil {
		return fmt.Errorf("get new code object address: %w", err)
	}
	adapterOwner, err := registry.GetNewCodeObjectOwnerAddress(nil, []byte(seed))
	if err != nil {
		return fmt.Errorf("get new code object owner address: %w", err)
	}
	fmt.Printf("seed %q -> adapter will live at %v, owned by MCMS account %v\n", seed, adapterAddr.StringLong(), adapterOwner.StringLong())

	payload, err := compile.CompilePackage(contracts.ForwarderMcmsAdapter, map[string]aptos.AccountAddress{
		"forwarder_mcms_adapter":    adapterAddr,
		"mcms":                      mcmsAddr,
		"mcms_owner":                {}, // 0x0; MCMS dep's named address, unused here
		"dummy_forwarder":           fwdAddr,
		"dummy_forwarder_secondary": fwd2Addr,
		// only needed to compile the forwarder deps
		"owner":           e.deployer.AccountAddress(),
		"owner_secondary": e.deployer.AccountAddress(),
	})
	if err != nil {
		return fmt.Errorf("compile adapter: %w", err)
	}

	// stage_code_chunk ... + stage_code_chunk_and_publish_to_object(seed), each an MCMS op that
	// timelock_dispatch routes to mcms_deployer.
	ops, err := utils.CreateChunksAndStage(payload, mcmsContract, uint64(e.chainSelector), seed, nil)
	if err != nil {
		return fmt.Errorf("create publish ops: %w", err)
	}
	fmt.Printf("publishing in %d MCMS op(s)\n", len(ops))
	if err := e.executeProposal("Publish forwarder_mcms_adapter", ops); err != nil {
		return fmt.Errorf("publish adapter via MCMS: %w", err)
	}

	e.st.Adapter = adapterAddr.StringLong()
	e.st.AdapterSeed = seed
	e.st.AdapterOwner = adapterOwner.StringLong()
	if err := e.saveState(); err != nil {
		return err
	}

	// Verify: the registered owner (signer MCMS uses for adapter calls) is the seed's owner account,
	// that account owns the adapter code object, and mcms_registry tracks it as MCMS-owned code.
	adapter := bind.NewBoundContract(adapterAddr, string(contracts.ForwarderMcmsAdapter), adapterModule, e.client)
	var registered aptos.AccountAddress
	if err := e.view(adapter, "mcms_owner_address", &registered); err != nil {
		return err
	}
	if registered != adapterOwner {
		return fmt.Errorf("adapter::mcms_owner_address is %v, expected %v", registered.StringLong(), adapterOwner.StringLong())
	}
	codeOwner, err := e.objectOwner(adapterAddr)
	if err != nil {
		return fmt.Errorf("read adapter code object owner: %w", err)
	}
	if codeOwner != adapterOwner {
		return fmt.Errorf("adapter code object owner is %v, expected %v", codeOwner.StringLong(), adapterOwner.StringLong())
	}
	owned, err := registry.IsOwnedCodeObject(nil, adapterAddr)
	if err != nil {
		return fmt.Errorf("is_owned_code_object: %w", err)
	}
	if !owned {
		return fmt.Errorf("mcms_registry does not report the adapter as an MCMS-owned code object")
	}
	fmt.Printf("✅ adapter published by MCMS at %v; its code and its forwarder calls are both owned by MCMS account %v\n",
		e.st.Adapter, e.st.AdapterOwner)
	return nil
}

// ===== step: transfer-to-mcms =====

func (e *env) transferToMCMS() error {
	fmt.Println("\n== transfer forwarder ownership to MCMS (via adapter) ==")
	adapterOwner, err := e.addr("adapter MCMS owner", e.st.AdapterOwner)
	if err != nil {
		return err
	}
	ts, err := e.targets()
	if err != nil {
		return err
	}

	// 1. current owner (deployer here, native multisig in prod) proposes the adapter's MCMS owner
	var calls []adapterCall
	for _, t := range ts {
		fwd, fwdAddr, err := e.forwarder(t)
		if err != nil {
			return err
		}
		module, fn, typeTags, args, err := fwd.Encode("transfer_ownership", nil, []string{"address"}, []any{adapterOwner})
		if err != nil {
			return err
		}
		tx, err := fwd.Transact(e.opts(), module, fn, typeTags, args)
		if _, err := e.wait(err, tx); err != nil {
			return fmt.Errorf("%s forwarder::transfer_ownership: %w", t.name, err)
		}
		fmt.Printf("deployer called %s forwarder::transfer_ownership(%v) (tx %v)\n", t.name, adapterOwner.StringLong(), tx.Hash)

		data, err := bcsArgs([]string{"address"}, []any{fwdAddr})
		if err != nil {
			return err
		}
		calls = append(calls, adapterCall{function: "accept_ownership", data: data})
	}

	// 2. ONE MCMS proposal accepts for every target through the adapter; only MCMS can produce
	//    the adapter owner's signer
	if err := e.executeAdapterCalls("Accept forwarder ownership", calls...); err != nil {
		return err
	}

	for _, t := range ts {
		_, owner, _, err := e.forwarderState(t)
		if err != nil {
			return err
		}
		if owner != adapterOwner {
			return fmt.Errorf("%s forwarder owner is %v, expected %v", t.name, owner.StringLong(), adapterOwner.StringLong())
		}
		fmt.Printf("✅ %s forwarder is now owned by the adapter's MCMS owner account\n", t.name)
		if err := e.printForwarder(t); err != nil {
			return err
		}
	}
	return nil
}

// ===== step: mcms-set-value =====

// mcmsSetValue sets value n on primary and n+1 on secondary (so we can tell them apart) in a
// single MCMS proposal, then checks the deployer can no longer call either forwarder directly.
func (e *env) mcmsSetValue(n uint64) error {
	ts, err := e.targets()
	if err != nil {
		return err
	}
	want := map[string]uint64{"primary": n, "secondary": n + 1}

	var calls []adapterCall
	for _, t := range ts {
		_, fwdAddr, err := e.forwarder(t)
		if err != nil {
			return err
		}
		fmt.Printf("\n== MCMS sets %s forwarder value to %d (via adapter) ==\n", t.name, want[t.name])
		data, err := bcsArgs([]string{"address", "u64"}, []any{fwdAddr, want[t.name]})
		if err != nil {
			return err
		}
		calls = append(calls, adapterCall{function: "set_value", data: data})
	}
	if err := e.executeAdapterCalls(fmt.Sprintf("Set values from %d", n), calls...); err != nil {
		return err
	}

	for _, t := range ts {
		value, _, _, err := e.forwarderState(t)
		if err != nil {
			return err
		}
		if value != want[t.name] {
			return fmt.Errorf("%s forwarder value is %d, expected %d", t.name, value, want[t.name])
		}
		fmt.Printf("✅ %s forwarder value set to %d through MCMS\n", t.name, value)

		// The deployer is no longer the owner, so a direct call must abort with E_NOT_OWNER.
		err = e.setValueDirect(t, 999)
		if err == nil {
			return fmt.Errorf("expected direct set_value on %s by deployer to fail after ownership transfer", t.name)
		}
		// 327687 = 0x50007 = error::permission_denied(E_NOT_OWNER)
		if !strings.Contains(err.Error(), "0x50007") && !strings.Contains(err.Error(), "327687") {
			return fmt.Errorf("direct set_value on %s failed with an unexpected error: %w", t.name, err)
		}
		fmt.Printf("✅ direct set_value on %s by the old owner is rejected (E_NOT_OWNER)\n", t.name)
	}
	return nil
}

// ===== step: mcms-bad-target =====

// mcmsBadTarget checks the adapter refuses to act on any address other than the two forwarders.
func (e *env) mcmsBadTarget() error {
	fmt.Println("\n== MCMS calls adapter::set_value on an unknown forwarder (must fail) ==")
	bogus := aptos.AccountAddress{}
	bogus[31] = 0xba
	bogus[30] = 0xd0
	data, err := bcsArgs([]string{"address", "u64"}, []any{bogus, uint64(1)})
	if err != nil {
		return err
	}
	err = e.executeAdapterCalls("Set value on unknown forwarder", adapterCall{function: "set_value", data: data})
	if err == nil {
		return fmt.Errorf("expected the adapter to reject an unknown forwarder address")
	}
	// 65538 = 0x10002 = error::invalid_argument(E_UNKNOWN_FORWARDER)
	if !strings.Contains(err.Error(), "0x10002") && !strings.Contains(err.Error(), "65538") {
		return fmt.Errorf("bad-target call failed with an unexpected error: %w", err)
	}
	fmt.Println("✅ adapter rejected the unknown forwarder (E_UNKNOWN_FORWARDER)")
	return nil
}

// ===== step: mcms-transfer-back =====

func (e *env) transferBack() error {
	fmt.Println("\n== MCMS hands forwarder ownership back to the deployer ==")
	ts, err := e.targets()
	if err != nil {
		return err
	}
	var calls []adapterCall
	for _, t := range ts {
		_, fwdAddr, err := e.forwarder(t)
		if err != nil {
			return err
		}
		data, err := bcsArgs([]string{"address", "address"}, []any{fwdAddr, e.deployer.AccountAddress()})
		if err != nil {
			return err
		}
		calls = append(calls, adapterCall{function: "transfer_ownership", data: data})
	}
	if err := e.executeAdapterCalls("Transfer forwarder ownership to deployer", calls...); err != nil {
		return err
	}
	for _, t := range ts {
		fwd, _, err := e.forwarder(t)
		if err != nil {
			return err
		}
		module, fn, typeTags, args, err := fwd.Encode("accept_ownership", nil, nil, nil)
		if err != nil {
			return err
		}
		tx, err := fwd.Transact(e.opts(), module, fn, typeTags, args)
		if _, err := e.wait(err, tx); err != nil {
			return fmt.Errorf("%s forwarder::accept_ownership: %w", t.name, err)
		}
		fmt.Printf("deployer accepted %s ownership (tx %v)\n", t.name, tx.Hash)
		if err := e.printForwarder(t); err != nil {
			return err
		}
	}
	return nil
}

// bcsArgs BCS-encodes the args and concatenates them, which is the `data` format MCMS passes to
// mcms_entrypoint (decoded there with mcms::bcs_stream).
func bcsArgs(types []string, values []any) ([]byte, error) {
	c := bind.NewBoundContract(aptos.AccountAddress{}, "", "", nil)
	_, _, _, args, err := c.Encode("", nil, types, values)
	if err != nil {
		return nil, err
	}
	return aptossdk.ArgsToData(args), nil
}
