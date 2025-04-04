// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_token_admin_registry

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type TokenAdminRegistry interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error)
	GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error)
	GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error)
	GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error)
	IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error)

	SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() TokenAdminRegistryEncoder
}

type TokenAdminRegistryEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPools(localTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenConfig(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllConfiguredTokens(startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptAdminRole(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertCanRegister(registryOwnerAddress aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress, fungibleAssetMetadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StartLockOrBurn(tokenPoolAddress aptos.AccountAddress, sender aptos.AccountAddress, remoteChainSelector uint64, receiver []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishLockOrBurn(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishReleaseOrMint(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"token_admin_registry","name":"accept_admin_role","parameters":[{"name":"local_token","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"assert_can_register","parameters":[{"name":"registry_owner_address","type":"address"},{"name":"token_pool_address","type":"address"},{"name":"fungible_asset_metadata","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_lock_or_burn","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_release_or_mint","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"set_pool","parameters":[{"name":"local_token","type":"address"},{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"start_lock_or_burn","parameters":[{"name":"token_pool_address","type":"address"},{"name":"sender","type":"address"},{"name":"remote_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"token_admin_registry","name":"transfer_admin_role","parameters":[{"name":"local_token","type":"address"},{"name":"new_admin","type":"address"}]}]`

func NewTokenAdminRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenAdminRegistry {
	contract := bind.NewBoundContract(address, "ccip", "token_admin_registry", client)
	return TokenAdminRegistryContract{
		BoundContract:             contract,
		tokenAdminRegistryEncoder: tokenAdminRegistryEncoder{BoundContract: contract},
	}
}

// Structs

type TokenAdminRegistryState struct {
}

type TokenConfig struct {
	TokenPoolAddress     aptos.AccountAddress `move:"address"`
	Administrator        aptos.AccountAddress `move:"address"`
	PendingAdministrator aptos.AccountAddress `move:"address"`
}

type TokenPoolRegistration struct {
	DispatchMetadata               bind.StdObject         `move:"aptos_framework::object::Object"`
	DispatchDepositFungibleStore   bind.StdObject         `move:"aptos_framework::object::Object"`
	ExecutionState                 byte                   `move:"u8"`
	ExecutingLockOrBurnInputV1     *LockOrBurnInputV1     `move:"std::option::Option<LockOrBurnInputV1>"`
	ExecutingReleaseOrMintInputV1  *ReleaseOrMintInputV1  `move:"std::option::Option<ReleaseOrMintInputV1>"`
	ExecutingLockOrBurnOutputV1    *LockOrBurnOutputV1    `move:"std::option::Option<LockOrBurnOutputV1>"`
	ExecutingReleaseOrMintOutputV1 *ReleaseOrMintOutputV1 `move:"std::option::Option<ReleaseOrMintOutputV1>"`
}

type LockOrBurnInputV1 struct {
	Sender              aptos.AccountAddress `move:"address"`
	RemoteChainSelector uint64               `move:"u64"`
	Receiver            []byte               `move:"vector<u8>"`
}

type LockOrBurnOutputV1 struct {
	DestTokenAddress []byte `move:"vector<u8>"`
	DestPoolData     []byte `move:"vector<u8>"`
}

type ReleaseOrMintInputV1 struct {
	Sender              []byte               `move:"vector<u8>"`
	Receiver            aptos.AccountAddress `move:"address"`
	SourceAmount        *big.Int             `move:"u256"`
	LocalToken          aptos.AccountAddress `move:"address"`
	RemoteChainSelector uint64               `move:"u64"`
	SourcePoolAddress   []byte               `move:"vector<u8>"`
	SourcePoolData      []byte               `move:"vector<u8>"`
	OffchainTokenData   []byte               `move:"vector<u8>"`
}

type ReleaseOrMintOutputV1 struct {
	DestinationAmount uint64 `move:"u64"`
}

type PoolSet struct {
	LocalToken          aptos.AccountAddress `move:"address"`
	PreviousPoolAddress aptos.AccountAddress `move:"address"`
	NewPoolAddress      aptos.AccountAddress `move:"address"`
}

type AdministratorTransferRequested struct {
	LocalToken   aptos.AccountAddress `move:"address"`
	CurrentAdmin aptos.AccountAddress `move:"address"`
	NewAdmin     aptos.AccountAddress `move:"address"`
}

type AdministratorTransferred struct {
	LocalToken aptos.AccountAddress `move:"address"`
	NewAdmin   aptos.AccountAddress `move:"address"`
}

type McmsCallback struct {
}

type TokenAdminRegistryContract struct {
	*bind.BoundContract
	tokenAdminRegistryEncoder
}

var _ TokenAdminRegistry = TokenAdminRegistryContract{}

func (c TokenAdminRegistryContract) Encoder() TokenAdminRegistryEncoder {
	return c.tokenAdminRegistryEncoder
}

// View Functions

func (c TokenAdminRegistryContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.TypeAndVersion()
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

func (c TokenAdminRegistryContract) GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetPools(localTokens)
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

func (c TokenAdminRegistryContract) GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetPool(localToken)
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

func (c TokenAdminRegistryContract) GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetTokenConfig(localToken)
	if err != nil {
		return *new(aptos.AccountAddress), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
		r1 aptos.AccountAddress
		r2 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new(aptos.AccountAddress), *new(aptos.AccountAddress), *new(aptos.AccountAddress), err
	}
	return r0, r1, r2, nil
}

func (c TokenAdminRegistryContract) GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetAllConfiguredTokens(startingBucketIndex, startingVectorIndex, maxCount)
	if err != nil {
		return *new([]aptos.AccountAddress), *new(*uint64), *new(*uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]aptos.AccountAddress), *new(*uint64), *new(*uint64), err
	}

	var (
		r0 []aptos.AccountAddress
		r1 bind.StdOption[uint64]
		r2 bind.StdOption[uint64]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new([]aptos.AccountAddress), *new(*uint64), *new(*uint64), err
	}
	return r0, r1.Value(), r2.Value(), nil
}

func (c TokenAdminRegistryContract) IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.IsAdministrator(localToken, administrator)
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

// Entry Functions

func (c TokenAdminRegistryContract) SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.SetPool(localToken, tokenPoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryContract) TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.TransferAdminRole(localToken, newAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryContract) AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.AcceptAdminRole(localToken)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type tokenAdminRegistryEncoder struct {
	*bind.BoundContract
}

func (c tokenAdminRegistryEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c tokenAdminRegistryEncoder) GetPools(localTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pools", nil, []string{
		"vector<address>",
	}, []any{
		localTokens,
	})
}

func (c tokenAdminRegistryEncoder) GetPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pool", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c tokenAdminRegistryEncoder) GetTokenConfig(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_config", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c tokenAdminRegistryEncoder) GetAllConfiguredTokens(startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_all_configured_tokens", nil, []string{
		"u64",
		"u64",
		"u64",
	}, []any{
		startingBucketIndex,
		startingVectorIndex,
		maxCount,
	})
}

func (c tokenAdminRegistryEncoder) IsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_administrator", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		administrator,
	})
}

func (c tokenAdminRegistryEncoder) SetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_pool", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) TransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_admin_role", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		newAdmin,
	})
}

func (c tokenAdminRegistryEncoder) AcceptAdminRole(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_admin_role", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c tokenAdminRegistryEncoder) AssertCanRegister(registryOwnerAddress aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress, fungibleAssetMetadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_can_register", nil, []string{
		"address",
		"address",
		"address",
	}, []any{
		registryOwnerAddress,
		tokenPoolAddress,
		fungibleAssetMetadata,
	})
}

func (c tokenAdminRegistryEncoder) StartLockOrBurn(tokenPoolAddress aptos.AccountAddress, sender aptos.AccountAddress, remoteChainSelector uint64, receiver []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("start_lock_or_burn", nil, []string{
		"address",
		"address",
		"u64",
		"vector<u8>",
	}, []any{
		tokenPoolAddress,
		sender,
		remoteChainSelector,
		receiver,
	})
}

func (c tokenAdminRegistryEncoder) FinishLockOrBurn(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_lock_or_burn", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) FinishReleaseOrMint(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_release_or_mint", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
