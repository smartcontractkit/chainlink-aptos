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
	GetPoolLocalToken(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	GetPoolLocalTokenV2(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	HasTokenPoolRegistrationV2(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (bool, error)
	GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error)
	GetAllConfiguredTokens(opts *bind.CallOpts, startKey aptos.AccountAddress, maxCount uint64) ([]aptos.AccountAddress, aptos.AccountAddress, bool, error)
	IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error)

	UnregisterPool(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error)
	SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	ProposeAdministrator(opts *bind.TransactOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() TokenAdminRegistryEncoder
}

type TokenAdminRegistryEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPools(localTokens []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPoolLocalToken(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPoolLocalTokenV2(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasTokenPoolRegistrationV2(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTokenConfig(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllConfiguredTokens(startKey aptos.AccountAddress, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UnregisterPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ProposeAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptAdminRole(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StartLockOrBurn(tokenPoolAddress aptos.AccountAddress, sender aptos.AccountAddress, remoteChainSelector uint64, receiver []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishLockOrBurn(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishReleaseOrMint(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"token_admin_registry","name":"accept_admin_role","parameters":[{"name":"local_token","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_lock_or_burn","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"finish_release_or_mint","parameters":[{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"propose_administrator","parameters":[{"name":"local_token","type":"address"},{"name":"administrator","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip","module":"token_admin_registry","name":"set_pool","parameters":[{"name":"local_token","type":"address"},{"name":"token_pool_address","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"start_lock_or_burn","parameters":[{"name":"token_pool_address","type":"address"},{"name":"sender","type":"address"},{"name":"remote_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"token_admin_registry","name":"transfer_admin_role","parameters":[{"name":"local_token","type":"address"},{"name":"new_admin","type":"address"}]},{"package":"ccip","module":"token_admin_registry","name":"unregister_pool","parameters":[{"name":"local_token","type":"address"}]}]`

func NewTokenAdminRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenAdminRegistryInterface {
	contract := bind.NewBoundContract(address, "ccip", "token_admin_registry", client)
	return TokenAdminRegistryContract{
		BoundContract:             contract,
		tokenAdminRegistryEncoder: tokenAdminRegistryEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_INVALID_FUNGIBLE_ASSET           uint64 = 1
	E_NOT_FUNGIBLE_ASSET_OWNER         uint64 = 2
	E_INVALID_TOKEN_POOL               uint64 = 3
	E_ALREADY_REGISTERED               uint64 = 4
	E_UNKNOWN_FUNCTION                 uint64 = 5
	E_PROOF_NOT_IN_TOKEN_POOL_MODULE   uint64 = 6
	E_PROOF_NOT_AT_TOKEN_POOL_ADDRESS  uint64 = 7
	E_UNKNOWN_PROOF_TYPE               uint64 = 8
	E_NOT_IN_IDLE_STATE                uint64 = 9
	E_NOT_IN_LOCK_OR_BURN_STATE        uint64 = 10
	E_NOT_IN_RELEASE_OR_MINT_STATE     uint64 = 11
	E_NON_EMPTY_LOCK_OR_BURN_INPUT     uint64 = 12
	E_NON_EMPTY_LOCK_OR_BURN_OUTPUT    uint64 = 13
	E_NON_EMPTY_RELEASE_OR_MINT_INPUT  uint64 = 14
	E_NON_EMPTY_RELEASE_OR_MINT_OUTPUT uint64 = 15
	E_MISSING_LOCK_OR_BURN_INPUT       uint64 = 16
	E_MISSING_LOCK_OR_BURN_OUTPUT      uint64 = 17
	E_MISSING_RELEASE_OR_MINT_INPUT    uint64 = 18
	E_MISSING_RELEASE_OR_MINT_OUTPUT   uint64 = 19
	E_TOKEN_POOL_NOT_OBJECT            uint64 = 20
	E_ADMIN_FOR_TOKEN_ALREADY_SET      uint64 = 21
	E_FUNGIBLE_ASSET_NOT_REGISTERED    uint64 = 22
	E_NOT_ADMINISTRATOR                uint64 = 23
	E_NOT_PENDING_ADMINISTRATOR        uint64 = 24
	E_NOT_AUTHORIZED                   uint64 = 25
	E_INVALID_TOKEN_FOR_POOL           uint64 = 26
	E_ADMIN_NOT_SET_FOR_TOKEN          uint64 = 27
	E_ADMIN_ALREADY_SET_FOR_TOKEN      uint64 = 28
	E_ZERO_ADDRESS                     uint64 = 29
	E_POOL_NOT_REGISTERED              uint64 = 30
	E_TOKEN_MISMATCH                   uint64 = 31
)

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
	ExecutingLockOrBurnInputV1     *LockOrBurnInputV1     `move:"0x1::option::Option<LockOrBurnInputV1>"`
	ExecutingReleaseOrMintInputV1  *ReleaseOrMintInputV1  `move:"0x1::option::Option<ReleaseOrMintInputV1>"`
	ExecutingLockOrBurnOutputV1    *LockOrBurnOutputV1    `move:"0x1::option::Option<LockOrBurnOutputV1>"`
	ExecutingReleaseOrMintOutputV1 *ReleaseOrMintOutputV1 `move:"0x1::option::Option<ReleaseOrMintOutputV1>"`
	LocalToken                     aptos.AccountAddress   `move:"address"`
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

type TokenPoolCallbacks struct {
}

type TokenPoolRegistrationV2 struct {
	Callbacks  TokenPoolCallbacks   `move:"TokenPoolCallbacks"`
	LocalToken aptos.AccountAddress `move:"address"`
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

type TokenUnregistered struct {
	LocalToken          aptos.AccountAddress `move:"address"`
	PreviousPoolAddress aptos.AccountAddress `move:"address"`
}

type McmsCallback struct {
}

type TokenAdminRegistryContract struct {
	*bind.BoundContract
	tokenAdminRegistryEncoder
}

var _ TokenAdminRegistryInterface = TokenAdminRegistryContract{}

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

func (c TokenAdminRegistryContract) GetPoolLocalToken(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetPoolLocalToken(tokenPoolAddress)
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

func (c TokenAdminRegistryContract) GetPoolLocalTokenV2(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetPoolLocalTokenV2(tokenPoolAddress)
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

func (c TokenAdminRegistryContract) HasTokenPoolRegistrationV2(opts *bind.CallOpts, tokenPoolAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.HasTokenPoolRegistrationV2(tokenPoolAddress)
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

func (c TokenAdminRegistryContract) GetAllConfiguredTokens(opts *bind.CallOpts, startKey aptos.AccountAddress, maxCount uint64) ([]aptos.AccountAddress, aptos.AccountAddress, bool, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.GetAllConfiguredTokens(startKey, maxCount)
	if err != nil {
		return *new([]aptos.AccountAddress), *new(aptos.AccountAddress), *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]aptos.AccountAddress), *new(aptos.AccountAddress), *new(bool), err
	}

	var (
		r0 []aptos.AccountAddress
		r1 aptos.AccountAddress
		r2 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new([]aptos.AccountAddress), *new(aptos.AccountAddress), *new(bool), err
	}
	return r0, r1, r2, nil
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

func (c TokenAdminRegistryContract) UnregisterPool(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.UnregisterPool(localToken)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryContract) SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.SetPool(localToken, tokenPoolAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c TokenAdminRegistryContract) ProposeAdministrator(opts *bind.TransactOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.tokenAdminRegistryEncoder.ProposeAdministrator(localToken, administrator)
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

func (c tokenAdminRegistryEncoder) GetPoolLocalToken(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pool_local_token", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) GetPoolLocalTokenV2(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pool_local_token_v2", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) HasTokenPoolRegistrationV2(tokenPoolAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_token_pool_registration_v2", nil, []string{
		"address",
	}, []any{
		tokenPoolAddress,
	})
}

func (c tokenAdminRegistryEncoder) GetTokenConfig(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_token_config", nil, []string{
		"address",
	}, []any{
		localToken,
	})
}

func (c tokenAdminRegistryEncoder) GetAllConfiguredTokens(startKey aptos.AccountAddress, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_all_configured_tokens", nil, []string{
		"address",
		"u64",
	}, []any{
		startKey,
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

func (c tokenAdminRegistryEncoder) UnregisterPool(localToken aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("unregister_pool", nil, []string{
		"address",
	}, []any{
		localToken,
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

func (c tokenAdminRegistryEncoder) ProposeAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("propose_administrator", nil, []string{
		"address",
		"address",
	}, []any{
		localToken,
		administrator,
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

func (c tokenAdminRegistryEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}
