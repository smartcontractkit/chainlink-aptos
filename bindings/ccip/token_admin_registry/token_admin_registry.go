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

type TokenAdminRegistryInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error)
	GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error)
	GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error)
	GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error)
	IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error)

	SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"ccip","module":"token_admin_registry","name":"accept_admin_role","parameters":[{"name":"local_token","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_lock_or_burn","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_release_or_mint","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"set_pool","parameters":[{"name":"local_token","type":"address"},{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"transfer_admin_role","parameters":[{"name":"local_token","type":"address"},{"name":"new_admin","type":"address"}]}]`

// Structs

type TokenAdminRegistryState struct {
}

type TokenConfig struct {
	TokenPoolAddress     aptos.AccountAddress `move:"address"`
	Administrator        aptos.AccountAddress `move:"address"`
	PendingAdministrator aptos.AccountAddress `move:"address"`
}

type TokenPoolRegistration struct {
	ExecutionState                 byte                   `move:"u8"`
	ExecutingLockOrBurnInputV1     *LockOrBurnInputV1     `move:"0x1::option::Option<LockOrBurnInputV1>"`
	ExecutingReleaseOrMintInputV1  *ReleaseOrMintInputV1  `move:"0x1::option::Option<ReleaseOrMintInputV1>"`
	ExecutingLockOrBurnOutputV1    *LockOrBurnOutputV1    `move:"0x1::option::Option<LockOrBurnOutputV1>"`
	ExecutingReleaseOrMintOutputV1 *ReleaseOrMintOutputV1 `move:"0x1::option::Option<ReleaseOrMintOutputV1>"`
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

type TokenAdminRegistry struct {
	TokenAdminRegistryCaller
	TokenAdminRegistryTransactor
}

// View Functions

type TokenAdminRegistryCaller struct {
	*bind.BoundContract
}

func (c TokenAdminRegistryCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c TokenAdminRegistryCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.EncodeTypeAndVersion()
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

func (c TokenAdminRegistryCaller) EncodeGetPools(localTokens []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pools", nil, []string{
		"vector<address>",
	}, []any{
		localTokens,
	})
}

func (c TokenAdminRegistryCaller) GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeGetPools(localTokens)
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

func (c TokenAdminRegistryCaller) EncodeGetPool(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pool", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryCaller) GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeGetPool(localToken)
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

func (c TokenAdminRegistryCaller) EncodeGetTokenConfig(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_config", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryCaller) GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeGetTokenConfig(localToken)
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

func (c TokenAdminRegistryCaller) EncodeGetAllConfiguredTokens(startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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

func (c TokenAdminRegistryCaller) GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetAllConfiguredTokens(startingBucketIndex, startingVectorIndex, maxCount)
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

func (c TokenAdminRegistryCaller) EncodeIsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_administrator", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		administrator,
	})
}

func (c TokenAdminRegistryCaller) IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.EncodeIsAdministrator(localToken, administrator)
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

type TokenAdminRegistryTransactor struct {
	*bind.BoundContract
}

func (c TokenAdminRegistryTransactor) EncodeSetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_pool", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		tokenPoolAddress,
	})
}

func (c TokenAdminRegistryTransactor) SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeSetPool(localToken, tokenPoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryTransactor) EncodeTransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_admin_role", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		newAdmin,
	})
}

func (c TokenAdminRegistryTransactor) TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeTransferAdminRole(localToken, newAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryTransactor) EncodeAcceptAdminRole(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_admin_role", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c TokenAdminRegistryTransactor) AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeAcceptAdminRole(localToken)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c TokenAdminRegistryCaller) EncodeFinishLockOrBurn(tokenPoolAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_lock_or_burn", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c TokenAdminRegistryCaller) EncodeFinishReleaseOrMint(tokenPoolAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_release_or_mint", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}
