// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_regulated_token_pool

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_rate_limiter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type RegulatedTokenPoolInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetToken(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetRouter(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetTokenDecimals(opts *bind.CallOpts) (byte, error)
	GetRemotePools(opts *bind.CallOpts, remoteChainSelector uint64) ([][]byte, error)
	IsRemotePool(opts *bind.CallOpts, remoteChainSelector uint64, remotePoolAddress []byte) (bool, error)
	GetRemoteToken(opts *bind.CallOpts, remoteChainSelector uint64) ([]byte, error)
	IsSupportedChain(opts *bind.CallOpts, remoteChainSelector uint64) (bool, error)
	GetSupportedChains(opts *bind.CallOpts) ([]uint64, error)
	GetAllowlistEnabled(opts *bind.CallOpts) (bool, error)
	GetAllowlist(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetCurrentInboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error)
	GetCurrentOutboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error)
	GetStoreAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	AddRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error)
	RemoveRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error)
	ApplyChainUpdates(opts *bind.TransactOpts, remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (*api.PendingTransaction, error)
	SetAllowlistEnabled(opts *bind.TransactOpts, enabled bool) (*api.PendingTransaction, error)
	ApplyAllowlistUpdates(opts *bind.TransactOpts, removes []aptos.AccountAddress, adds []aptos.AccountAddress) (*api.PendingTransaction, error)
	SetChainRateLimiterConfigs(opts *bind.TransactOpts, remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (*api.PendingTransaction, error)
	SetChainRateLimiterConfig(opts *bind.TransactOpts, remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RegulatedTokenPoolEncoder
}

type RegulatedTokenPoolEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetToken() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRouter() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenDecimals() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRemotePools(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRemoteToken(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsSupportedChain(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetSupportedChains() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowlistEnabled() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowlist() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetCurrentInboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetCurrentOutboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AddRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RemoveRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyChainUpdates(remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetAllowlistEnabled(enabled bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowlistUpdates(removes []aptos.AccountAddress, adds []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetChainRateLimiterConfigs(remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetChainRateLimiterConfig(remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterV2Callbacks() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint(moduleName []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"regulated_token_pool","module":"regulated_token_pool","name":"accept_ownership","parameters":null},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"add_remote_pool","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"remote_pool_address","type":"vector\u003cu8\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"apply_allowlist_updates","parameters":[{"name":"removes","type":"vector\u003caddress\u003e"},{"name":"adds","type":"vector\u003caddress\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"apply_chain_updates","parameters":[{"name":"remote_chain_selectors_to_remove","type":"vector\u003cu64\u003e"},{"name":"remote_chain_selectors_to_add","type":"vector\u003cu64\u003e"},{"name":"remote_pool_addresses_to_add","type":"vector\u003cvector\u003cvector\u003cu8\u003e\u003e\u003e"},{"name":"remote_token_addresses_to_add","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"register_mcms_entrypoint","parameters":[{"name":"module_name","type":"vector\u003cu8\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"register_v2_callbacks","parameters":null},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"remove_remote_pool","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"remote_pool_address","type":"vector\u003cu8\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"set_allowlist_enabled","parameters":[{"name":"enabled","type":"bool"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"set_chain_rate_limiter_config","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"outbound_is_enabled","type":"bool"},{"name":"outbound_capacity","type":"u64"},{"name":"outbound_rate","type":"u64"},{"name":"inbound_is_enabled","type":"bool"},{"name":"inbound_capacity","type":"u64"},{"name":"inbound_rate","type":"u64"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"set_chain_rate_limiter_configs","parameters":[{"name":"remote_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"outbound_is_enableds","type":"vector\u003cbool\u003e"},{"name":"outbound_capacities","type":"vector\u003cu64\u003e"},{"name":"outbound_rates","type":"vector\u003cu64\u003e"},{"name":"inbound_is_enableds","type":"vector\u003cbool\u003e"},{"name":"inbound_capacities","type":"vector\u003cu64\u003e"},{"name":"inbound_rates","type":"vector\u003cu64\u003e"}]},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"store_address","parameters":null},{"package":"regulated_token_pool","module":"regulated_token_pool","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewRegulatedTokenPool(address aptos.AccountAddress, client aptos.AptosRpcClient) RegulatedTokenPoolInterface {
	contract := bind.NewBoundContract(address, "regulated_token_pool", "regulated_token_pool", client)
	return RegulatedTokenPoolContract{
		BoundContract:             contract,
		regulatedTokenPoolEncoder: regulatedTokenPoolEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_INVALID_ARGUMENTS uint64 = 1
	E_UNKNOWN_FUNCTION  uint64 = 2
	E_NOT_PUBLISHER     uint64 = 3
)

// Structs

type RegulatedTokenPoolState struct {
	StoreSignerAddress aptos.AccountAddress `move:"address"`
}

type CallbackProof struct {
}

type McmsCallback struct {
}

type RegulatedTokenPoolContract struct {
	*bind.BoundContract
	regulatedTokenPoolEncoder
}

var _ RegulatedTokenPoolInterface = RegulatedTokenPoolContract{}

func (c RegulatedTokenPoolContract) Encoder() RegulatedTokenPoolEncoder {
	return c.regulatedTokenPoolEncoder
}

// View Functions

func (c RegulatedTokenPoolContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.TypeAndVersion()
	if err != nil {
		return *new(string), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(string), err
	}

	var (
		r0 string
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(string), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetToken(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetToken()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetRouter(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetRouter()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetTokenDecimals(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetTokenDecimals()
	if err != nil {
		return *new(byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(byte), err
	}

	var (
		r0 byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(byte), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetRemotePools(opts *bind.CallOpts, remoteChainSelector uint64) ([][]byte, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetRemotePools(remoteChainSelector)
	if err != nil {
		return *new([][]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([][]byte), err
	}

	var (
		r0 [][]byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([][]byte), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) IsRemotePool(opts *bind.CallOpts, remoteChainSelector uint64, remotePoolAddress []byte) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.IsRemotePool(remoteChainSelector, remotePoolAddress)
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetRemoteToken(opts *bind.CallOpts, remoteChainSelector uint64) ([]byte, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetRemoteToken(remoteChainSelector)
	if err != nil {
		return *new([]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), err
	}

	var (
		r0 []byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]byte), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) IsSupportedChain(opts *bind.CallOpts, remoteChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.IsSupportedChain(remoteChainSelector)
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetSupportedChains(opts *bind.CallOpts) ([]uint64, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetSupportedChains()
	if err != nil {
		return *new([]uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]uint64), err
	}

	var (
		r0 []uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]uint64), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetAllowlistEnabled(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetAllowlistEnabled()
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetAllowlist(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetAllowlist()
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	var (
		r0 []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]aptos.AccountAddress), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetCurrentInboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetCurrentInboundRateLimiterState(remoteChainSelector)
	if err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}

	var (
		r0 module_rate_limiter.TokenBucket
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetCurrentOutboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetCurrentOutboundRateLimiterState(remoteChainSelector)
	if err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}

	var (
		r0 module_rate_limiter.TokenBucket
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(module_rate_limiter.TokenBucket), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) GetStoreAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.GetStoreAddress()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.Owner()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.HasPendingTransfer()
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RegulatedTokenPoolContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.PendingTransferFrom()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c RegulatedTokenPoolContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.PendingTransferTo()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c RegulatedTokenPoolContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.PendingTransferAccepted()
	if err != nil {
		return *new(*bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bool), err
	}

	var (
		r0 bind.StdOption[bool]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bool), err
	}
	return r0.Value(), nil
}

// Entry Functions

func (c RegulatedTokenPoolContract) AddRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.AddRemotePool(remoteChainSelector, remotePoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) RemoveRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.RemoveRemotePool(remoteChainSelector, remotePoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) ApplyChainUpdates(opts *bind.TransactOpts, remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.ApplyChainUpdates(remoteChainSelectorsToRemove, remoteChainSelectorsToAdd, remotePoolAddressesToAdd, remoteTokenAddressesToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) SetAllowlistEnabled(opts *bind.TransactOpts, enabled bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.SetAllowlistEnabled(enabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) ApplyAllowlistUpdates(opts *bind.TransactOpts, removes []aptos.AccountAddress, adds []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.ApplyAllowlistUpdates(removes, adds)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) SetChainRateLimiterConfigs(opts *bind.TransactOpts, remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.SetChainRateLimiterConfigs(remoteChainSelectors, outboundIsEnableds, outboundCapacities, outboundRates, inboundIsEnableds, inboundCapacities, inboundRates)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) SetChainRateLimiterConfig(opts *bind.TransactOpts, remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.SetChainRateLimiterConfig(remoteChainSelector, outboundIsEnabled, outboundCapacity, outboundRate, inboundIsEnabled, inboundCapacity, inboundRate)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenPoolContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenPoolEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type regulatedTokenPoolEncoder struct {
	*bind.BoundContract
}

func (c regulatedTokenPoolEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetToken() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetRouter() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_router", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetTokenDecimals() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_decimals", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetRemotePools(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_remote_pools", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c regulatedTokenPoolEncoder) IsRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c regulatedTokenPoolEncoder) GetRemoteToken(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_remote_token", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c regulatedTokenPoolEncoder) IsSupportedChain(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_supported_chain", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c regulatedTokenPoolEncoder) GetSupportedChains() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_supported_chains", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetAllowlistEnabled() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowlist_enabled", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetAllowlist() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowlist", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) GetCurrentInboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_current_inbound_rate_limiter_state", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c regulatedTokenPoolEncoder) GetCurrentOutboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_current_outbound_rate_limiter_state", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c regulatedTokenPoolEncoder) GetStoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_store_address", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) AddRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("add_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c regulatedTokenPoolEncoder) RemoveRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("remove_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c regulatedTokenPoolEncoder) ApplyChainUpdates(remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_chain_updates", nil, []string{
		"vector<u64>",
		"vector<u64>",
		"vector<vector<vector<u8>>>",
		"vector<vector<u8>>",
	}, []any{
		remoteChainSelectorsToRemove,
		remoteChainSelectorsToAdd,
		remotePoolAddressesToAdd,
		remoteTokenAddressesToAdd,
	})
}

func (c regulatedTokenPoolEncoder) SetAllowlistEnabled(enabled bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_allowlist_enabled", nil, []string{
		"bool",
	}, []any{
		enabled,
	})
}

func (c regulatedTokenPoolEncoder) ApplyAllowlistUpdates(removes []aptos.AccountAddress, adds []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowlist_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		removes,
		adds,
	})
}

func (c regulatedTokenPoolEncoder) SetChainRateLimiterConfigs(remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_chain_rate_limiter_configs", nil, []string{
		"vector<u64>",
		"vector<bool>",
		"vector<u64>",
		"vector<u64>",
		"vector<bool>",
		"vector<u64>",
		"vector<u64>",
	}, []any{
		remoteChainSelectors,
		outboundIsEnableds,
		outboundCapacities,
		outboundRates,
		inboundIsEnableds,
		inboundCapacities,
		inboundRates,
	})
}

func (c regulatedTokenPoolEncoder) SetChainRateLimiterConfig(remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_chain_rate_limiter_config", nil, []string{
		"u64",
		"bool",
		"u64",
		"u64",
		"bool",
		"u64",
		"u64",
	}, []any{
		remoteChainSelector,
		outboundIsEnabled,
		outboundCapacity,
		outboundRate,
		inboundIsEnabled,
		inboundCapacity,
		inboundRate,
	})
}

func (c regulatedTokenPoolEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c regulatedTokenPoolEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c regulatedTokenPoolEncoder) RegisterV2Callbacks() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_v2_callbacks", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) StoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("store_address", nil, []string{}, []any{})
}

func (c regulatedTokenPoolEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c regulatedTokenPoolEncoder) RegisterMCMSEntrypoint(moduleName []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{
		"vector<u8>",
	}, []any{
		moduleName,
	})
}
