// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_usdc_token_pool

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

type USDCTokenPoolInterface interface {
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
	GetDomain(opts *bind.CallOpts, chainSelector uint64) (Domain, error)
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
	Encoder() USDCTokenPoolEncoder
}

type USDCTokenPoolEncoder interface {
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
	GetDomain(chainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
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
	Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ParseMessageAndAttestation(payload []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	EncodeDestPoolData(localDomainIdentifier uint32, nonce uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DecodeDestPoolData(destPoolData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetDomains(remoteChainSelectors []uint64, remoteDomainIdentifiers []uint32, allowedRemoteCallers [][]byte, enableds []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertCanInitialize(callerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint(moduleName []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"usdc_token_pool","module":"usdc_token_pool","name":"accept_ownership","parameters":null},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"add_remote_pool","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"remote_pool_address","type":"vector\u003cu8\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"apply_allowlist_updates","parameters":[{"name":"removes","type":"vector\u003caddress\u003e"},{"name":"adds","type":"vector\u003caddress\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"apply_chain_updates","parameters":[{"name":"remote_chain_selectors_to_remove","type":"vector\u003cu64\u003e"},{"name":"remote_chain_selectors_to_add","type":"vector\u003cu64\u003e"},{"name":"remote_pool_addresses_to_add","type":"vector\u003cvector\u003cvector\u003cu8\u003e\u003e\u003e"},{"name":"remote_token_addresses_to_add","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"assert_can_initialize","parameters":[{"name":"caller_address","type":"address"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"decode_dest_pool_data","parameters":[{"name":"dest_pool_data","type":"vector\u003cu8\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"encode_dest_pool_data","parameters":[{"name":"local_domain_identifier","type":"u32"},{"name":"nonce","type":"u64"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"initialize","parameters":null},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"parse_message_and_attestation","parameters":[{"name":"payload","type":"vector\u003cu8\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"register_mcms_entrypoint","parameters":[{"name":"module_name","type":"vector\u003cu8\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"register_v2_callbacks","parameters":null},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"remove_remote_pool","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"remote_pool_address","type":"vector\u003cu8\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"set_allowlist_enabled","parameters":[{"name":"enabled","type":"bool"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"set_chain_rate_limiter_config","parameters":[{"name":"remote_chain_selector","type":"u64"},{"name":"outbound_is_enabled","type":"bool"},{"name":"outbound_capacity","type":"u64"},{"name":"outbound_rate","type":"u64"},{"name":"inbound_is_enabled","type":"bool"},{"name":"inbound_capacity","type":"u64"},{"name":"inbound_rate","type":"u64"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"set_chain_rate_limiter_configs","parameters":[{"name":"remote_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"outbound_is_enableds","type":"vector\u003cbool\u003e"},{"name":"outbound_capacities","type":"vector\u003cu64\u003e"},{"name":"outbound_rates","type":"vector\u003cu64\u003e"},{"name":"inbound_is_enableds","type":"vector\u003cbool\u003e"},{"name":"inbound_capacities","type":"vector\u003cu64\u003e"},{"name":"inbound_rates","type":"vector\u003cu64\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"set_domains","parameters":[{"name":"remote_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"remote_domain_identifiers","type":"vector\u003cu32\u003e"},{"name":"allowed_remote_callers","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"enableds","type":"vector\u003cbool\u003e"}]},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"store_address","parameters":null},{"package":"usdc_token_pool","module":"usdc_token_pool","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewUSDCTokenPool(address aptos.AccountAddress, client aptos.AptosRpcClient) USDCTokenPoolInterface {
	contract := bind.NewBoundContract(address, "usdc_token_pool", "usdc_token_pool", client)
	return USDCTokenPoolContract{
		BoundContract:        contract,
		usdcTokenPoolEncoder: usdcTokenPoolEncoder{BoundContract: contract},
	}
}

// Constants
const (
	SUPPORTED_USDC_VERSION     uint32 = 0
	E_NOT_PUBLISHER            uint64 = 1
	E_ALREADY_INITIALIZED      uint64 = 2
	E_INVALID_FUNGIBLE_ASSET   uint64 = 3
	E_INVALID_ARGUMENTS        uint64 = 4
	E_DOMAIN_NOT_FOUND         uint64 = 5
	E_DOMAIN_ENABLED           uint64 = 6
	E_UNKNOWN_FUNCTION         uint64 = 7
	E_DOMAIN_MISMATCH          uint64 = 8
	E_NONCE_MISMATCH           uint64 = 9
	E_DESTINATION_MISMATCH     uint64 = 10
	E_DOMAIN_DISABLED          uint64 = 11
	E_ZERO_CHAIN_SELECTOR      uint64 = 12
	E_EMPTY_ALLOWED_CALLER     uint64 = 13
	E_INVALID_MESSAGE_VERSION  uint64 = 14
	E_ZERO_ADDRESS_NOT_ALLOWED uint64 = 15
)

// Structs

type USDCTokenPoolDeployment struct {
}

type USDCTokenPoolState struct {
	LocalDomainIdentifier uint32               `move:"u32"`
	StoreSignerAddress    aptos.AccountAddress `move:"address"`
}

type Domain struct {
	AllowedCaller    []byte `move:"vector<u8>"`
	DomainIdentifier uint32 `move:"u32"`
	Enabled          bool   `move:"bool"`
}

type DomainsSet struct {
	AllowedCaller       []byte `move:"vector<u8>"`
	DomainIdentifier    uint32 `move:"u32"`
	RemoteChainSelector uint64 `move:"u64"`
	Enabled             bool   `move:"bool"`
}

type CallbackProof struct {
}

type McmsCallback struct {
}

type USDCTokenPoolContract struct {
	*bind.BoundContract
	usdcTokenPoolEncoder
}

var _ USDCTokenPoolInterface = USDCTokenPoolContract{}

func (c USDCTokenPoolContract) Encoder() USDCTokenPoolEncoder {
	return c.usdcTokenPoolEncoder
}

// View Functions

func (c USDCTokenPoolContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.TypeAndVersion()
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

func (c USDCTokenPoolContract) GetToken(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetToken()
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

func (c USDCTokenPoolContract) GetRouter(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetRouter()
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

func (c USDCTokenPoolContract) GetTokenDecimals(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetTokenDecimals()
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

func (c USDCTokenPoolContract) GetRemotePools(opts *bind.CallOpts, remoteChainSelector uint64) ([][]byte, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetRemotePools(remoteChainSelector)
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

func (c USDCTokenPoolContract) IsRemotePool(opts *bind.CallOpts, remoteChainSelector uint64, remotePoolAddress []byte) (bool, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.IsRemotePool(remoteChainSelector, remotePoolAddress)
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

func (c USDCTokenPoolContract) GetRemoteToken(opts *bind.CallOpts, remoteChainSelector uint64) ([]byte, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetRemoteToken(remoteChainSelector)
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

func (c USDCTokenPoolContract) IsSupportedChain(opts *bind.CallOpts, remoteChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.IsSupportedChain(remoteChainSelector)
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

func (c USDCTokenPoolContract) GetSupportedChains(opts *bind.CallOpts) ([]uint64, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetSupportedChains()
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

func (c USDCTokenPoolContract) GetAllowlistEnabled(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetAllowlistEnabled()
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

func (c USDCTokenPoolContract) GetAllowlist(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetAllowlist()
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

func (c USDCTokenPoolContract) GetDomain(opts *bind.CallOpts, chainSelector uint64) (Domain, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetDomain(chainSelector)
	if err != nil {
		return *new(Domain), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(Domain), err
	}

	var (
		r0 Domain
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(Domain), err
	}
	return r0, nil
}

func (c USDCTokenPoolContract) GetCurrentInboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetCurrentInboundRateLimiterState(remoteChainSelector)
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

func (c USDCTokenPoolContract) GetCurrentOutboundRateLimiterState(opts *bind.CallOpts, remoteChainSelector uint64) (module_rate_limiter.TokenBucket, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetCurrentOutboundRateLimiterState(remoteChainSelector)
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

func (c USDCTokenPoolContract) GetStoreAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.GetStoreAddress()
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

func (c USDCTokenPoolContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.Owner()
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

func (c USDCTokenPoolContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.HasPendingTransfer()
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

func (c USDCTokenPoolContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.PendingTransferFrom()
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

func (c USDCTokenPoolContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.PendingTransferTo()
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

func (c USDCTokenPoolContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.PendingTransferAccepted()
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

func (c USDCTokenPoolContract) AddRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.AddRemotePool(remoteChainSelector, remotePoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) RemoveRemotePool(opts *bind.TransactOpts, remoteChainSelector uint64, remotePoolAddress []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.RemoveRemotePool(remoteChainSelector, remotePoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) ApplyChainUpdates(opts *bind.TransactOpts, remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.ApplyChainUpdates(remoteChainSelectorsToRemove, remoteChainSelectorsToAdd, remotePoolAddressesToAdd, remoteTokenAddressesToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) SetAllowlistEnabled(opts *bind.TransactOpts, enabled bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.SetAllowlistEnabled(enabled)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) ApplyAllowlistUpdates(opts *bind.TransactOpts, removes []aptos.AccountAddress, adds []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.ApplyAllowlistUpdates(removes, adds)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) SetChainRateLimiterConfigs(opts *bind.TransactOpts, remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.SetChainRateLimiterConfigs(remoteChainSelectors, outboundIsEnableds, outboundCapacities, outboundRates, inboundIsEnableds, inboundCapacities, inboundRates)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) SetChainRateLimiterConfig(opts *bind.TransactOpts, remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.SetChainRateLimiterConfig(remoteChainSelector, outboundIsEnabled, outboundCapacity, outboundRate, inboundIsEnabled, inboundCapacity, inboundRate)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c USDCTokenPoolContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.usdcTokenPoolEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type usdcTokenPoolEncoder struct {
	*bind.BoundContract
}

func (c usdcTokenPoolEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetToken() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetRouter() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_router", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetTokenDecimals() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_decimals", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetRemotePools(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_remote_pools", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c usdcTokenPoolEncoder) IsRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c usdcTokenPoolEncoder) GetRemoteToken(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_remote_token", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c usdcTokenPoolEncoder) IsSupportedChain(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_supported_chain", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c usdcTokenPoolEncoder) GetSupportedChains() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_supported_chains", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetAllowlistEnabled() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowlist_enabled", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetAllowlist() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowlist", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) GetDomain(chainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_domain", nil, []string{
		"u64",
	}, []any{
		chainSelector,
	})
}

func (c usdcTokenPoolEncoder) GetCurrentInboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_current_inbound_rate_limiter_state", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c usdcTokenPoolEncoder) GetCurrentOutboundRateLimiterState(remoteChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_current_outbound_rate_limiter_state", nil, []string{
		"u64",
	}, []any{
		remoteChainSelector,
	})
}

func (c usdcTokenPoolEncoder) GetStoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_store_address", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) AddRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("add_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c usdcTokenPoolEncoder) RemoveRemotePool(remoteChainSelector uint64, remotePoolAddress []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("remove_remote_pool", nil, []string{
		"u64",
		"vector<u8>",
	}, []any{
		remoteChainSelector,
		remotePoolAddress,
	})
}

func (c usdcTokenPoolEncoder) ApplyChainUpdates(remoteChainSelectorsToRemove []uint64, remoteChainSelectorsToAdd []uint64, remotePoolAddressesToAdd [][][]byte, remoteTokenAddressesToAdd [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c usdcTokenPoolEncoder) SetAllowlistEnabled(enabled bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_allowlist_enabled", nil, []string{
		"bool",
	}, []any{
		enabled,
	})
}

func (c usdcTokenPoolEncoder) ApplyAllowlistUpdates(removes []aptos.AccountAddress, adds []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowlist_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		removes,
		adds,
	})
}

func (c usdcTokenPoolEncoder) SetChainRateLimiterConfigs(remoteChainSelectors []uint64, outboundIsEnableds []bool, outboundCapacities []uint64, outboundRates []uint64, inboundIsEnableds []bool, inboundCapacities []uint64, inboundRates []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c usdcTokenPoolEncoder) SetChainRateLimiterConfig(remoteChainSelector uint64, outboundIsEnabled bool, outboundCapacity uint64, outboundRate uint64, inboundIsEnabled bool, inboundCapacity uint64, inboundRate uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c usdcTokenPoolEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c usdcTokenPoolEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c usdcTokenPoolEncoder) RegisterV2Callbacks() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_v2_callbacks", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) ParseMessageAndAttestation(payload []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("parse_message_and_attestation", nil, []string{
		"vector<u8>",
	}, []any{
		payload,
	})
}

func (c usdcTokenPoolEncoder) EncodeDestPoolData(localDomainIdentifier uint32, nonce uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("encode_dest_pool_data", nil, []string{
		"u32",
		"u64",
	}, []any{
		localDomainIdentifier,
		nonce,
	})
}

func (c usdcTokenPoolEncoder) DecodeDestPoolData(destPoolData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("decode_dest_pool_data", nil, []string{
		"vector<u8>",
	}, []any{
		destPoolData,
	})
}

func (c usdcTokenPoolEncoder) SetDomains(remoteChainSelectors []uint64, remoteDomainIdentifiers []uint32, allowedRemoteCallers [][]byte, enableds []bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_domains", nil, []string{
		"vector<u64>",
		"vector<u32>",
		"vector<vector<u8>>",
		"vector<bool>",
	}, []any{
		remoteChainSelectors,
		remoteDomainIdentifiers,
		allowedRemoteCallers,
		enableds,
	})
}

func (c usdcTokenPoolEncoder) StoreAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("store_address", nil, []string{}, []any{})
}

func (c usdcTokenPoolEncoder) AssertCanInitialize(callerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_can_initialize", nil, []string{
		"address",
	}, []any{
		callerAddress,
	})
}

func (c usdcTokenPoolEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c usdcTokenPoolEncoder) RegisterMCMSEntrypoint(moduleName []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{
		"vector<u8>",
	}, []any{
		moduleName,
	})
}
