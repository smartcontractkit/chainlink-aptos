// Package forwarder_mcms_adapter binds the ChainlinkForwarderMcmsAdapter package
// (contracts/forwarder_mcms_adapter).
//
// The adapter has no entry functions of its own: MCMS reaches it through the dispatch hook, and
// mcms_entrypoint routes on the function name carried by the MCMS operation. The four call names
// below are therefore not Move functions, so this binding is hand-written rather than generated.
// Each call's data is the BCS concatenation of its arguments, with the target forwarder address
// first (see the module docs in contracts/forwarder_mcms_adapter/sources/adapter.move).
package forwarder_mcms_adapter

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

const (
	// ModuleName is the adapter's only module; MCMS operations target <adapter>::adapter::<call>.
	ModuleName = "adapter"

	FunctionSetConfig         = "set_config"
	FunctionClearConfig       = "clear_config"
	FunctionTransferOwnership = "transfer_ownership"
	FunctionAcceptOwnership   = "accept_ownership"
)

// NamedAddresses are the named addresses the adapter package is compiled with.
type NamedAddresses struct {
	// Adapter is the address the package is published at. When published through mcms_deployer
	// this is mcms_registry::get_new_code_object_address(seed).
	Adapter aptos.AccountAddress
	// MCMS is the MCMS instance that will govern the forwarders.
	MCMS aptos.AccountAddress
	// Platform and PlatformSecondary are the two deployed forwarder packages.
	Platform          aptos.AccountAddress
	PlatformSecondary aptos.AccountAddress
	// Owner and OwnerSecondary are only needed to compile the forwarder dependencies.
	Owner          aptos.AccountAddress
	OwnerSecondary aptos.AccountAddress
}

func (n NamedAddresses) toMap() map[string]aptos.AccountAddress {
	return map[string]aptos.AccountAddress{
		"forwarder_mcms_adapter": n.Adapter,
		"mcms":                   n.MCMS,
		"platform":               n.Platform,
		"platform_secondary":     n.PlatformSecondary,
		"owner":                  n.Owner,
		"owner_secondary":        n.OwnerSecondary,
	}
}

// Compile compiles the adapter package with the Aptos CLI.
func Compile(addresses NamedAddresses) (compile.CompiledPackage, error) {
	return compile.CompilePackage(contracts.ForwarderMcmsAdapter, addresses.toMap())
}

// Adapter is a bound, deployed adapter.
type Adapter struct {
	address  aptos.AccountAddress
	contract *bind.BoundContract
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) Adapter {
	return Adapter{
		address:  address,
		contract: bind.NewBoundContract(address, string(contracts.ForwarderMcmsAdapter), ModuleName, client),
	}
}

func (a Adapter) Address() aptos.AccountAddress {
	return a.address
}

// MCMSOwnerAddress returns the account MCMS signs as through this adapter. Both forwarders' owner
// must be this address for MCMS to govern them.
func (a Adapter) MCMSOwnerAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	var out aptos.AccountAddress
	res, err := a.view(opts, "mcms_owner_address")
	if err != nil {
		return out, err
	}
	if len(res) != 1 {
		return out, fmt.Errorf("mcms_owner_address: expected 1 value, got %d", len(res))
	}
	return parseAddress(res[0])
}

// Forwarders returns the (primary, secondary) forwarder addresses the adapter was compiled against.
func (a Adapter) Forwarders(opts *bind.CallOpts) (aptos.AccountAddress, aptos.AccountAddress, error) {
	res, err := a.view(opts, "forwarders")
	if err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	if len(res) != 2 {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, fmt.Errorf("forwarders: expected 2 values, got %d", len(res))
	}
	primary, err := parseAddress(res[0])
	if err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	secondary, err := parseAddress(res[1])
	if err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	return primary, secondary, nil
}

func (a Adapter) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	res, err := a.view(opts, "type_and_version")
	if err != nil {
		return "", err
	}
	if len(res) != 1 {
		return "", fmt.Errorf("type_and_version: expected 1 value, got %d", len(res))
	}
	s, ok := res[0].(string)
	if !ok {
		return "", fmt.Errorf("type_and_version: unexpected value %v", res[0])
	}
	return s, nil
}

func (a Adapter) view(opts *bind.CallOpts, function string) ([]any, error) {
	module, fn, typeTags, args, err := a.contract.Encode(function, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	res, err := a.contract.Call(opts, module, fn, typeTags, args)
	if err != nil {
		return nil, fmt.Errorf("view %s: %w", function, err)
	}
	return res, nil
}

func parseAddress(v any) (aptos.AccountAddress, error) {
	var out aptos.AccountAddress
	s, ok := v.(string)
	if !ok {
		return out, fmt.Errorf("expected address string, got %T", v)
	}
	if err := out.ParseStringRelaxed(s); err != nil {
		return out, fmt.Errorf("parse address %q: %w", s, err)
	}
	return out, nil
}

// Encoder returns the MCMS call encoder for this adapter.
func (a Adapter) Encoder() Encoder {
	return NewEncoder(a.address)
}

// Encoder encodes the adapter's MCMS calls. Each method returns the module, the function name
// and the call data as a single argument, ready for an MCMS transaction targeting the adapter.
type Encoder struct {
	module bind.ModuleInformation
}

func NewEncoder(adapter aptos.AccountAddress) Encoder {
	return Encoder{module: bind.ModuleInformation{
		PackageName: string(contracts.ForwarderMcmsAdapter),
		ModuleName:  ModuleName,
		Address:     adapter,
	}}
}

// SetConfig encodes forwarder::set_config(don_id, config_version, f, oracles) on the target forwarder.
func (e Encoder) SetConfig(forwarder aptos.AccountAddress, donID, configVersion uint32, f uint8, oracles [][]byte) (bind.ModuleInformation, string, []byte, error) {
	data, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		forwarder.MarshalBCS(ser)
		ser.U32(donID)
		ser.U32(configVersion)
		ser.U8(f)
		bcs.SerializeSequenceWithFunction(oracles, ser, func(ser *bcs.Serializer, key []byte) {
			ser.WriteBytes(key)
		})
	})
	return e.module, FunctionSetConfig, data, err
}

// ClearConfig encodes forwarder::clear_config(don_id, config_version) on the target forwarder.
func (e Encoder) ClearConfig(forwarder aptos.AccountAddress, donID, configVersion uint32) (bind.ModuleInformation, string, []byte, error) {
	data, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		forwarder.MarshalBCS(ser)
		ser.U32(donID)
		ser.U32(configVersion)
	})
	return e.module, FunctionClearConfig, data, err
}

// TransferOwnership encodes forwarder::transfer_ownership(to) on the target forwarder.
func (e Encoder) TransferOwnership(forwarder, to aptos.AccountAddress) (bind.ModuleInformation, string, []byte, error) {
	data, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		forwarder.MarshalBCS(ser)
		to.MarshalBCS(ser)
	})
	return e.module, FunctionTransferOwnership, data, err
}

// AcceptOwnership encodes forwarder::accept_ownership() on the target forwarder.
func (e Encoder) AcceptOwnership(forwarder aptos.AccountAddress) (bind.ModuleInformation, string, []byte, error) {
	data, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		forwarder.MarshalBCS(ser)
	})
	return e.module, FunctionAcceptOwnership, data, err
}
