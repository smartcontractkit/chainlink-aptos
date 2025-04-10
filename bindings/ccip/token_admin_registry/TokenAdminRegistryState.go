// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_TokenAdminRegistryState

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

type TokenAdminRegistryState interface {
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
	Encoder() TokenAdminRegistryStateEncoder
}

type TokenAdminRegistryStateEncoder interface {
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
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"fungible_asset","module":"TokenAdminRegistryState","name":"accept_admin_role","parameters":[{"name":"local_token","type":"address"}]},{"package":"fungible_asset","module":"TokenAdminRegistryState","name":"assert_can_register","parameters":[{"name":"registry_owner_address","type":"address"},{"name":"token_pool_address","type":"address"},{"name":"fungible_asset_metadata","type":"address"}]},{"package":"fungible_asset","module":"TokenAdminRegistryState","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"fungible_asset","module":"TokenAdminRegistryState","name":"set_pool","parameters":[{"name":"local_token","type":"address"},{"name":"token_pool_address","type":"address"}]},{"package":"fungible_asset","module":"TokenAdminRegistryState","name":"transfer_admin_role","parameters":[{"name":"local_token","type":"address"},{"name":"new_admin","type":"address"}]}]`

func NewTokenAdminRegistryState(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenAdminRegistryState {
	contract := bind.NewBoundContract(address, "fungible_asset", "TokenAdminRegistryState", client)
	return TokenAdminRegistryStateContract{
		BoundContract:                  contract,
		TokenAdminRegistryStateEncoder: TokenAdminRegistryStateEncoder{BoundContract: contract},
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

type TokenAdminRegistryStateContract struct {
	*bind.BoundContract
	TokenAdminRegistryStateEncoder
}

var _ TokenAdminRegistryState = TokenAdminRegistryStateContract{}

func (c TokenAdminRegistryStateContract) Encoder() TokenAdminRegistryStateEncoder {
	return c.TokenAdminRegistryStateEncoder
}

// View Functions

func (c TokenAdminRegistryStateContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.TypeAndVersion()
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

func (c TokenAdminRegistryStateContract) GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.GetPools(localTokens)
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

func (c TokenAdminRegistryStateContract) GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.GetPool(localToken)
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

func (c TokenAdminRegistryStateContract) GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.GetTokenConfig(localToken)
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

func (c TokenAdminRegistryStateContract) GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.GetAllConfiguredTokens(startingBucketIndex, startingVectorIndex, maxCount)
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

func (c TokenAdminRegistryStateContract) IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.IsAdministrator(localToken, administrator)
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

func (c TokenAdminRegistryStateContract) SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.SetPool(localToken, tokenPoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryStateContract) TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.TransferAdminRole(localToken, newAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryStateContract) AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.TokenAdminRegistryStateEncoder.AcceptAdminRole(localToken)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type TokenAdminRegistryStateEncoder struct {
	*bind.BoundContract
}

func (c TokenAdminRegistryStateEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c TokenAdminRegistryStateEncoder) GetPools(localTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pools", nil, []string{
		"vector<address>",
	}, []any{
		localTokens,
	})
}

func (c TokenAdminRegistryStateEncoder) GetPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pool", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryStateEncoder) GetTokenConfig(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_config", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryStateEncoder) GetAllConfiguredTokens(startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c TokenAdminRegistryStateEncoder) IsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_administrator", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		administrator,
	})
}

func (c TokenAdminRegistryStateEncoder) SetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_pool", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		tokenPoolAddress,
	})
}

func (c TokenAdminRegistryStateEncoder) TransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_admin_role", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		newAdmin,
	})
}

func (c TokenAdminRegistryStateEncoder) AcceptAdminRole(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_admin_role", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryStateEncoder) AssertCanRegister(registryOwnerAddress aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress, fungibleAssetMetadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c TokenAdminRegistryStateEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
