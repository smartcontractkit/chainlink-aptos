package cre

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	cldf_aptos "github.com/smartcontractkit/chainlink-deployments-framework/chain/aptos"
	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	adapterbind "github.com/smartcontractkit/chainlink-aptos/bindings/forwarder_mcms_adapter"
	mcmsbind "github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform_secondary"
)

// forwarderStateSeed is forwarder::APP_OBJECT_SEED: State lives at create_object_address(@platform, seed).
var forwarderStateSeed = []byte("FORWARDER")

func aptosChain(env cldf.Environment, chainSelector uint64) (cldf_aptos.Chain, error) {
	chain, ok := env.BlockChains.AptosChains()[chainSelector]
	if !ok {
		return cldf_aptos.Chain{}, fmt.Errorf("aptos chain %d not found in environment", chainSelector)
	}
	return chain, nil
}

// lookupRef reads one datastore ref at version 1.0.0.
func lookupRef(env cldf.Environment, chainSelector uint64, contractType cldf.ContractType, qualifier string) (aptos.AccountAddress, error) {
	var addr aptos.AccountAddress
	if env.DataStore == nil {
		return addr, errors.New("environment has no datastore")
	}
	version := Version1_0_0
	key := datastore.NewAddressRefKey(chainSelector, datastore.ContractType(contractType), &version, qualifier)
	ref, err := env.DataStore.Addresses().Get(key)
	if err != nil {
		return addr, fmt.Errorf("%s (qualifier %q) not found in datastore for chain %d: %w", contractType, qualifier, chainSelector, err)
	}
	if err := addr.ParseStringRelaxed(ref.Address); err != nil {
		return addr, fmt.Errorf("invalid %s address %q in datastore: %w", contractType, ref.Address, err)
	}
	return addr, nil
}

func forwarderAddress(env cldf.Environment, chainSelector uint64, zone Zone) (aptos.AccountAddress, error) {
	return lookupRef(env, chainSelector, AptosForwarderType, string(zone))
}

func mcmsAddress(env cldf.Environment, chainSelector uint64, qualifier string) (aptos.AccountAddress, error) {
	return lookupRef(env, chainSelector, AptosMCMSType, qualifier)
}

// adapterInfo is a deployed adapter: its package address and its MCMS owner account.
type adapterInfo struct {
	address aptos.AccountAddress
	owner   aptos.AccountAddress
}

// loadAdapter resolves the adapter from the datastore and cross-checks it on chain: the recorded
// owner must be the account the adapter actually signs as, and the adapter must have been
// compiled against the forwarders the datastore names for each zone.
func loadAdapter(env cldf.Environment, chain cldf_aptos.Chain, qualifier string) (adapterInfo, error) {
	addr, err := lookupRef(env, chain.Selector, AptosForwarderMcmsAdapterType, qualifier)
	if err != nil {
		return adapterInfo{}, err
	}
	recordedOwner, err := lookupRef(env, chain.Selector, AptosForwarderMcmsAdapterOwnerType, qualifier)
	if err != nil {
		return adapterInfo{}, err
	}
	adapter := adapterbind.Bind(addr, chain.Client)
	owner, err := adapter.MCMSOwnerAddress(nil)
	if err != nil {
		return adapterInfo{}, fmt.Errorf("read adapter %s on chain (has its publish proposal executed?): %w", addr.StringLong(), err)
	}
	if owner != recordedOwner {
		return adapterInfo{}, fmt.Errorf("adapter %s signs as %s but the datastore records owner %s", addr.StringLong(), owner.StringLong(), recordedOwner.StringLong())
	}
	primary, secondary, err := adapter.Forwarders(nil)
	if err != nil {
		return adapterInfo{}, err
	}
	for zone, onChain := range map[Zone]aptos.AccountAddress{ZoneA: primary, ZoneB: secondary} {
		fwd, err := forwarderAddress(env, chain.Selector, zone)
		if err != nil {
			return adapterInfo{}, err
		}
		if fwd != onChain {
			return adapterInfo{}, fmt.Errorf("adapter %s governs %s for %s, but the datastore's %s forwarder is %s",
				addr.StringLong(), onChain.StringLong(), zone, zone, fwd.StringLong())
		}
	}
	return adapterInfo{address: addr, owner: owner}, nil
}

// forwarderContract is the part of the (separately generated) platform and platform_secondary
// forwarder bindings this package uses.
type forwarderContract interface {
	GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	SetConfig(opts *bind.TransactOpts, donID uint32, configVersion uint32, f byte, oracles [][]byte) (*api.PendingTransaction, error)
	ClearConfig(opts *bind.TransactOpts, donID uint32, configVersion uint32) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

func bindForwarder(zone Zone, addr aptos.AccountAddress, client aptos.AptosRpcClient) forwarderContract {
	if zone == ZoneB {
		return platform_secondary.Bind(addr, client).Forwarder()
	}
	return platform.Bind(addr, client).Forwarder()
}

// forwarder is a zone's forwarder resolved from the datastore.
type forwarder struct {
	zone     Zone
	address  aptos.AccountAddress
	contract forwarderContract
}

func loadForwarder(env cldf.Environment, chain cldf_aptos.Chain, zone Zone) (forwarder, error) {
	addr, err := forwarderAddress(env, chain.Selector, zone)
	if err != nil {
		return forwarder{}, err
	}
	return forwarder{zone: zone, address: addr, contract: bindForwarder(zone, addr, chain.Client)}, nil
}

func (f forwarder) owner() (aptos.AccountAddress, error) {
	owner, err := f.contract.GetOwner(nil)
	if err != nil {
		return owner, fmt.Errorf("read owner of %s forwarder %s: %w", f.zone, f.address.StringLong(), err)
	}
	return owner, nil
}

// pendingOwner reads forwarder::State.pending_owner_address (the forwarder has no view for it).
func (f forwarder) pendingOwner(client aptos.AptosRpcClient) (aptos.AccountAddress, error) {
	var pending aptos.AccountAddress
	stateAddr := f.address.NamedObjectAddress(forwarderStateSeed)
	res, err := client.AccountResource(stateAddr, f.address.StringLong()+"::forwarder::State")
	if err != nil {
		return pending, fmt.Errorf("read State of %s forwarder %s: %w", f.zone, f.address.StringLong(), err)
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return pending, fmt.Errorf("unexpected State resource for %s forwarder: %v", f.zone, res)
	}
	s, ok := data["pending_owner_address"].(string)
	if !ok {
		return pending, fmt.Errorf("unexpected pending_owner_address for %s forwarder: %v", f.zone, data["pending_owner_address"])
	}
	return pending, pending.ParseStringRelaxed(s)
}

// configExists reports whether forwarder::get_config(don_id, config_version) succeeds.
func (f forwarder) configExists(client aptos.AptosRpcClient, donID, configVersion uint32) (bool, error) {
	c := bind.NewBoundContract(f.address, f.zone.PackageName(), forwarderModule, client)
	module, fn, typeTags, args, err := c.Encode("get_config", nil, []string{"u32", "u32"}, []any{donID, configVersion})
	if err != nil {
		return false, err
	}
	// get_config aborts (smart_table::borrow on a missing key) when the config does not exist;
	// anything else (RPC failure, wrong address) is a real error.
	if _, err := c.Call(nil, module, fn, typeTags, args); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "abort") {
			return false, nil
		}
		return false, fmt.Errorf("read config (%d, %d) of %s forwarder %s: %w", donID, configVersion, f.zone, f.address.StringLong(), err)
	}
	return true, nil
}

// requireOwner fails unless the forwarder is owned by want.
func (f forwarder) requireOwner(want aptos.AccountAddress, wantDesc string) error {
	owner, err := f.owner()
	if err != nil {
		return err
	}
	if owner != want {
		return fmt.Errorf("%s forwarder %s is owned by %s, not %s (%s)", f.zone, f.address.StringLong(), owner.StringLong(), wantDesc, want.StringLong())
	}
	return nil
}

// packageNames lists the Move package names published at addr.
func packageNames(client aptos.AptosRpcClient, addr aptos.AccountAddress) ([]string, error) {
	res, err := client.AccountResource(addr, "0x1::code::PackageRegistry")
	if err != nil {
		return nil, fmt.Errorf("read PackageRegistry at %s: %w", addr.StringLong(), err)
	}
	data, ok := res["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected PackageRegistry at %s", addr.StringLong())
	}
	pkgs, ok := data["packages"].([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected PackageRegistry packages at %s", addr.StringLong())
	}
	var names []string
	for _, p := range pkgs {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := m["name"].(string); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

// mcmsSelfOwned reports whether MCMS owns itself, which mcms_deployer requires before MCMS can
// publish code through a proposal.
func mcmsSelfOwned(client aptos.AptosRpcClient, mcmsAddr aptos.AccountAddress) (bool, error) {
	owner, err := mcmsbind.Bind(mcmsAddr, client).MCMSAccount().Owner(nil)
	if err != nil {
		return false, fmt.Errorf("read owner of MCMS %s: %w", mcmsAddr.StringLong(), err)
	}
	return owner == mcmsAddr, nil
}

func deployerAddress(chain cldf_aptos.Chain) (aptos.AccountAddress, error) {
	if chain.DeployerSigner == nil {
		return aptos.AccountAddress{}, fmt.Errorf("aptos chain %d has no deployer signer", chain.Selector)
	}
	return chain.DeployerSigner.AccountAddress(), nil
}
