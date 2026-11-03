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
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

const (
	forwarderModule = "forwarder"
	adapterModule   = "adapter"
)

func (e *env) opts() *bind.TransactOpts {
	return &bind.TransactOpts{Signer: e.deployer}
}

func (e *env) forwarder() (*bind.BoundContract, error) {
	a, err := e.addr("forwarder", e.st.Forwarder)
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(a, string(contracts.DummyForwarder), forwarderModule, e.client), nil
}

// ===== step: deploy-forwarder =====

func (e *env) deployForwarder() error {
	fmt.Println("\n== deploy dummy_forwarder ==")
	addr, tx, err := bind.DeployPackageToObject(e.deployer, e.client, contracts.DummyForwarder,
		map[string]aptos.AccountAddress{"owner": e.deployer.AccountAddress()},
		aptos.MaxGasAmount(e.flags.deployMaxGas),
	)
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("deploy dummy_forwarder: %w", err)
	}
	e.st.Forwarder = addr.StringLong()
	fmt.Printf("dummy_forwarder deployed at %v (tx %v), owner = deployer\n", e.st.Forwarder, tx.Hash)
	return e.saveState()
}

// ===== step: set-value (direct) =====

func (e *env) setValueDirect(n uint64) error {
	fmt.Printf("\n== deployer calls forwarder::set_value(%d) directly ==\n", n)
	fwd, err := e.forwarder()
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
	return e.printForwarder()
}

// ===== step: status =====

func (e *env) viewForwarder(fn string, out any) error {
	fwd, err := e.forwarder()
	if err != nil {
		return err
	}
	module, f, typeTags, args, err := fwd.Encode(fn, nil, nil, nil)
	if err != nil {
		return err
	}
	res, err := fwd.Call(nil, module, f, typeTags, args)
	if err != nil {
		return fmt.Errorf("view %s: %w", fn, err)
	}
	return codec.DecodeAptosJsonArray(res, out)
}

func (e *env) forwarderState() (value uint64, owner, pending aptos.AccountAddress, err error) {
	if err = e.viewForwarder("get_value", &value); err != nil {
		return
	}
	if err = e.viewForwarder("get_owner", &owner); err != nil {
		return
	}
	err = e.viewForwarder("get_pending_owner", &pending)
	return
}

func (e *env) printForwarder() error {
	value, owner, pending, err := e.forwarderState()
	if err != nil {
		return err
	}
	fmt.Printf("forwarder: value=%d owner=%v%s pending_owner=%v\n", value, owner.StringLong(), e.label(owner), pending.StringLong())
	return nil
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
	fmt.Printf("forwarder:          %v\n", e.st.Forwarder)
	fmt.Printf("mcms:               %v\n", e.st.MCMS)
	fmt.Printf("adapter:            %v\n", e.st.Adapter)
	fmt.Printf("adapter MCMS owner: %v\n", e.st.AdapterOwner)
	if e.st.Forwarder == "" {
		return nil
	}
	return e.printForwarder()
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

// ===== step: deploy-adapter =====

func (e *env) deployAdapter() error {
	fmt.Println("\n== deploy forwarder_mcms_adapter ==")
	mcmsAddr, err := e.addr("mcms", e.st.MCMS)
	if err != nil {
		return err
	}
	fwdAddr, err := e.addr("forwarder", e.st.Forwarder)
	if err != nil {
		return err
	}
	// The adapter is compiled against the already-deployed forwarder and MCMS (static deps).
	// Its init_module registers the adapter's mcms_entrypoint with mcms_registry.
	addr, tx, err := bind.DeployPackageToObject(e.deployer, e.client, contracts.ForwarderMcmsAdapter,
		map[string]aptos.AccountAddress{
			"mcms":            mcmsAddr,
			"dummy_forwarder": fwdAddr,
			"owner":           e.deployer.AccountAddress(), // only needed to compile the forwarder dep
		},
		aptos.MaxGasAmount(e.flags.deployMaxGas),
	)
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("deploy adapter: %w", err)
	}
	e.st.Adapter = addr.StringLong()
	fmt.Printf("adapter deployed at %v (tx %v)\n", e.st.Adapter, tx.Hash)

	owner, err := mcms.Bind(mcmsAddr, e.client).MCMSRegistry().GetRegisteredOwnerAddress(nil, addr)
	if err != nil {
		return fmt.Errorf("get adapter's registered MCMS owner: %w", err)
	}
	e.st.AdapterOwner = owner.StringLong()
	fmt.Printf("adapter's MCMS owner account (signer MCMS uses for adapter calls): %v\n", e.st.AdapterOwner)
	return e.saveState()
}

// ===== step: transfer-to-mcms =====

func (e *env) transferToMCMS() error {
	fmt.Println("\n== transfer forwarder ownership to MCMS (via adapter) ==")
	adapterOwner, err := e.addr("adapter MCMS owner", e.st.AdapterOwner)
	if err != nil {
		return err
	}
	fwd, err := e.forwarder()
	if err != nil {
		return err
	}

	// 1. current owner (deployer here, native multisig in prod) proposes the adapter's MCMS owner
	module, fn, typeTags, args, err := fwd.Encode("transfer_ownership", nil, []string{"address"}, []any{adapterOwner})
	if err != nil {
		return err
	}
	tx, err := fwd.Transact(e.opts(), module, fn, typeTags, args)
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("forwarder::transfer_ownership: %w", err)
	}
	fmt.Printf("deployer called forwarder::transfer_ownership(%v) (tx %v)\n", adapterOwner.StringLong(), tx.Hash)

	// 2. MCMS accepts through the adapter; only MCMS can produce the adapter owner's signer
	if err := e.executeAdapterCalls("Accept forwarder ownership", adapterCall{function: "accept_ownership"}); err != nil {
		return err
	}

	_, owner, _, err := e.forwarderState()
	if err != nil {
		return err
	}
	if owner != adapterOwner {
		return fmt.Errorf("forwarder owner is %v, expected %v", owner.StringLong(), adapterOwner.StringLong())
	}
	fmt.Println("✅ forwarder is now owned by the adapter's MCMS owner account")
	return e.printForwarder()
}

// ===== step: mcms-set-value =====

func (e *env) mcmsSetValue(n uint64) error {
	fmt.Printf("\n== MCMS sets forwarder value to %d (via adapter) ==\n", n)
	data, err := bcsArgs([]string{"u64"}, []any{n})
	if err != nil {
		return err
	}
	if err := e.executeAdapterCalls(fmt.Sprintf("Set value %d", n), adapterCall{function: "set_value", data: data}); err != nil {
		return err
	}
	value, _, _, err := e.forwarderState()
	if err != nil {
		return err
	}
	if value != n {
		return fmt.Errorf("forwarder value is %d, expected %d", value, n)
	}
	fmt.Printf("✅ forwarder value set to %d through MCMS\n", value)

	// The deployer is no longer the owner, so a direct call must abort with E_NOT_OWNER.
	err = e.setValueDirect(n + 1)
	if err == nil {
		return fmt.Errorf("expected direct set_value by deployer to fail after ownership transfer")
	}
	// 327687 = 0x50007 = error::permission_denied(E_NOT_OWNER)
	if !strings.Contains(err.Error(), "0x50007") && !strings.Contains(err.Error(), "327687") {
		return fmt.Errorf("direct set_value failed with an unexpected error: %w", err)
	}
	fmt.Println("✅ direct set_value by the old owner is rejected (E_NOT_OWNER)")
	return nil
}

// ===== step: mcms-transfer-back =====

func (e *env) transferBack() error {
	fmt.Println("\n== MCMS hands forwarder ownership back to the deployer ==")
	data, err := bcsArgs([]string{"address"}, []any{e.deployer.AccountAddress()})
	if err != nil {
		return err
	}
	if err := e.executeAdapterCalls("Transfer forwarder ownership to deployer", adapterCall{function: "transfer_ownership", data: data}); err != nil {
		return err
	}
	fwd, err := e.forwarder()
	if err != nil {
		return err
	}
	module, fn, typeTags, args, err := fwd.Encode("accept_ownership", nil, nil, nil)
	if err != nil {
		return err
	}
	tx, err := fwd.Transact(e.opts(), module, fn, typeTags, args)
	if _, err := e.wait(err, tx); err != nil {
		return fmt.Errorf("forwarder::accept_ownership: %w", err)
	}
	fmt.Printf("deployer accepted ownership (tx %v)\n", tx.Hash)
	return e.printForwarder()
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
