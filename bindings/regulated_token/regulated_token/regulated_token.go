// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_regulated_token

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

type RegulatedTokenInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenStateObject(opts *bind.CallOpts) (aptos.AccountAddress, error)
	Admin(opts *bind.CallOpts) (aptos.AccountAddress, error)
	PendingAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsPaused(opts *bind.CallOpts) (bool, error)
	GetRoleMembers(opts *bind.CallOpts, roleNumber byte) ([]aptos.AccountAddress, error)
	GetRoleMemberCount(opts *bind.CallOpts, roleNumber byte) (uint64, error)
	GetRoleMember(opts *bind.CallOpts, roleNumber byte, index uint64) (aptos.AccountAddress, error)
	GetAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetBridgeMintersOrBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetFreezers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetUnfreezers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetPausers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetUnpausers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetRecoveryManagers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetPendingAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsFrozen(opts *bind.CallOpts, account aptos.AccountAddress) (bool, error)
	GetAllFrozenAccounts(opts *bind.CallOpts, startKey aptos.AccountAddress, maxCount uint64) ([]aptos.AccountAddress, aptos.AccountAddress, bool, error)
	HasRole(opts *bind.CallOpts, account aptos.AccountAddress, role byte) (bool, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error)
	Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	GrantRole(opts *bind.TransactOpts, roleNumber byte, account aptos.AccountAddress) (*api.PendingTransaction, error)
	RevokeRole(opts *bind.TransactOpts, roleNumber byte, account aptos.AccountAddress) (*api.PendingTransaction, error)
	FreezeAccounts(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error)
	FreezeAccount(opts *bind.TransactOpts, account aptos.AccountAddress) (*api.PendingTransaction, error)
	UnfreezeAccounts(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error)
	UnfreezeAccount(opts *bind.TransactOpts, account aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyRoleUpdates(opts *bind.TransactOpts, roleNumber byte, addressesToRemove []aptos.AccountAddress, addressesToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	Pause(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	Unpause(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	BatchBurnFrozenFunds(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error)
	BurnFrozenFunds(opts *bind.TransactOpts, from aptos.AccountAddress) (*api.PendingTransaction, error)
	RecoverFrozenFunds(opts *bind.TransactOpts, from aptos.AccountAddress, to aptos.AccountAddress) (*api.PendingTransaction, error)
	BatchRecoverFrozenFunds(opts *bind.TransactOpts, accounts []aptos.AccountAddress, to aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferAdmin(opts *bind.TransactOpts, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptAdmin(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	RecoverTokens(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RegulatedTokenEncoder
}

type RegulatedTokenEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateObject() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Admin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsPaused() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRoleMembers(roleNumber byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRoleMemberCount(roleNumber byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRoleMember(roleNumber byte, index uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetBridgeMintersOrBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFreezers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetUnfreezers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPausers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetUnpausers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRecoveryManagers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPendingAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsFrozen(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllFrozenAccounts(startKey aptos.AccountAddress, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasRole(account aptos.AccountAddress, role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GrantRole(roleNumber byte, account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RevokeRole(roleNumber byte, account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FreezeAccounts(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FreezeAccount(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UnfreezeAccounts(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UnfreezeAccount(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyRoleUpdates(roleNumber byte, addressesToRemove []aptos.AccountAddress, addressesToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Pause() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Unpause() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	BatchBurnFrozenFunds(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	BurnFrozenFunds(from aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RecoverFrozenFunds(from aptos.AccountAddress, to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	BatchRecoverFrozenFunds(accounts []aptos.AccountAddress, to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferAdmin(newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RecoverTokens(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateObjectInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadataFromStateObj(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadataInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertPauser(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertUnpauser(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertFreezer(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertUnfreezer(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertRecoveryRole(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertBridgeMinterOrBurner(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertBurnerAndGetType(burner aptos.AccountAddress, stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"regulated_token","module":"regulated_token","name":"accept_admin","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"accept_ownership","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"apply_role_updates","parameters":[{"name":"role_number","type":"u8"},{"name":"addresses_to_remove","type":"vector\u003caddress\u003e"},{"name":"addresses_to_add","type":"vector\u003caddress\u003e"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_bridge_minter_or_burner","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_burner_and_get_type","parameters":[{"name":"burner","type":"address"},{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_freezer","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_pauser","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_recovery_role","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_unfreezer","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"assert_unpauser","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"batch_burn_frozen_funds","parameters":[{"name":"accounts","type":"vector\u003caddress\u003e"}]},{"package":"regulated_token","module":"regulated_token","name":"batch_recover_frozen_funds","parameters":[{"name":"accounts","type":"vector\u003caddress\u003e"},{"name":"to","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"burn","parameters":[{"name":"from","type":"address"},{"name":"amount","type":"u64"}]},{"package":"regulated_token","module":"regulated_token","name":"burn_frozen_funds","parameters":[{"name":"from","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"freeze_account","parameters":[{"name":"account","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"freeze_accounts","parameters":[{"name":"accounts","type":"vector\u003caddress\u003e"}]},{"package":"regulated_token","module":"regulated_token","name":"grant_role","parameters":[{"name":"role_number","type":"u8"},{"name":"account","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"initialize","parameters":[{"name":"max_supply","type":"0x1::option::Option\u003cu128\u003e"},{"name":"name","type":"0x1::string::String"},{"name":"symbol","type":"0x1::string::String"},{"name":"decimals","type":"u8"},{"name":"icon","type":"0x1::string::String"},{"name":"project","type":"0x1::string::String"}]},{"package":"regulated_token","module":"regulated_token","name":"mint","parameters":[{"name":"to","type":"address"},{"name":"amount","type":"u64"}]},{"package":"regulated_token","module":"regulated_token","name":"pause","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"recover_frozen_funds","parameters":[{"name":"from","type":"address"},{"name":"to","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"recover_tokens","parameters":[{"name":"to","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"revoke_role","parameters":[{"name":"role_number","type":"u8"},{"name":"account","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"token_metadata_from_state_obj","parameters":[{"name":"state_obj","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"token_metadata_internal","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"token_state_address_internal","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"token_state_object_internal","parameters":null},{"package":"regulated_token","module":"regulated_token","name":"transfer_admin","parameters":[{"name":"new_admin","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"unfreeze_account","parameters":[{"name":"account","type":"address"}]},{"package":"regulated_token","module":"regulated_token","name":"unfreeze_accounts","parameters":[{"name":"accounts","type":"vector\u003caddress\u003e"}]},{"package":"regulated_token","module":"regulated_token","name":"unpause","parameters":null}]`

func NewRegulatedToken(address aptos.AccountAddress, client aptos.AptosRpcClient) RegulatedTokenInterface {
	contract := bind.NewBoundContract(address, "regulated_token", "regulated_token", client)
	return RegulatedTokenContract{
		BoundContract:         contract,
		regulatedTokenEncoder: regulatedTokenEncoder{BoundContract: contract},
	}
}

// Constants
const (
	PAUSER_ROLE                                  byte   = 0
	UNPAUSER_ROLE                                byte   = 1
	FREEZER_ROLE                                 byte   = 2
	UNFREEZER_ROLE                               byte   = 3
	MINTER_ROLE                                  byte   = 4
	BURNER_ROLE                                  byte   = 5
	BRIDGE_MINTER_OR_BURNER_ROLE                 byte   = 6
	RECOVERY_ROLE                                byte   = 7
	E_NOT_PUBLISHER                              uint64 = 1
	E_TOKEN_NOT_INITIALIZED                      uint64 = 2
	E_ONLY_BURNER_OR_BRIDGE                      uint64 = 3
	E_ONLY_MINTER_OR_BRIDGE                      uint64 = 4
	E_INVALID_ASSET                              uint64 = 5
	E_ZERO_ADDRESS_NOT_ALLOWED                   uint64 = 6
	E_CANNOT_TRANSFER_TO_REGULATED_TOKEN         uint64 = 7
	E_PAUSED                                     uint64 = 8
	E_ACCOUNT_FROZEN                             uint64 = 9
	E_ALREADY_PAUSED                             uint64 = 14
	E_NOT_PAUSED                                 uint64 = 15
	E_INVALID_ROLE_NUMBER                        uint64 = 10
	E_INVALID_STORE                              uint64 = 11
	E_STORE_DOES_NOT_EXIST                       uint64 = 12
	E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED uint64 = 13
	E_ACCOUNT_MUST_BE_FROZEN_FOR_RECOVERY        uint64 = 14
)

// Structs

type TokenStateDeployment struct {
	Paused bool `move:"bool"`
}

type TokenState struct {
	Paused bool           `move:"bool"`
	Token  bind.StdObject `move:"aptos_framework::object::Object"`
}

type TokenMetadataRefs struct {
}

type InitializeToken struct {
	Publisher aptos.AccountAddress `move:"address"`
	Token     bind.StdObject       `move:"aptos_framework::object::Object"`
	MaxSupply **big.Int            `move:"0x1::option::Option<u128>"`
	Decimals  byte                 `move:"u8"`
	Icon      string               `move:"0x1::string::String"`
	Project   string               `move:"0x1::string::String"`
}

type NativeMint struct {
	Minter aptos.AccountAddress `move:"address"`
	To     aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type BridgeMint struct {
	Minter aptos.AccountAddress `move:"address"`
	To     aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type NativeBurn struct {
	Burner aptos.AccountAddress `move:"address"`
	From   aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type BridgeBurn struct {
	Burner aptos.AccountAddress `move:"address"`
	From   aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type MinterAdded struct {
	Admin         aptos.AccountAddress `move:"address"`
	Minter        aptos.AccountAddress `move:"address"`
	OperationType byte                 `move:"u8"`
}

type Paused struct {
	Pauser aptos.AccountAddress `move:"address"`
}

type Unpaused struct {
	Unpauser aptos.AccountAddress `move:"address"`
}

type AccountFrozen struct {
	Freezer aptos.AccountAddress `move:"address"`
	Account aptos.AccountAddress `move:"address"`
}

type AccountUnfrozen struct {
	Unfreezer aptos.AccountAddress `move:"address"`
	Account   aptos.AccountAddress `move:"address"`
}

type TokensRecovered struct {
	Caller        aptos.AccountAddress `move:"address"`
	TokenMetadata bind.StdObject       `move:"aptos_framework::object::Object"`
	From          aptos.AccountAddress `move:"address"`
	To            aptos.AccountAddress `move:"address"`
	Amount        uint64               `move:"u64"`
}

type RegulatedTokenContract struct {
	*bind.BoundContract
	regulatedTokenEncoder
}

var _ RegulatedTokenInterface = RegulatedTokenContract{}

func (c RegulatedTokenContract) Encoder() RegulatedTokenEncoder {
	return c.regulatedTokenEncoder
}

// View Functions

func (c RegulatedTokenContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TypeAndVersion()
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

func (c RegulatedTokenContract) TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TokenStateAddress()
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

func (c RegulatedTokenContract) TokenStateObject(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TokenStateObject()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 bind.StdObject
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0.Address(), nil
}

func (c RegulatedTokenContract) Admin(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Admin()
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

func (c RegulatedTokenContract) PendingAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.PendingAdmin()
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

func (c RegulatedTokenContract) TokenAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TokenAddress()
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

func (c RegulatedTokenContract) TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TokenMetadata()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 bind.StdObject
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0.Address(), nil
}

func (c RegulatedTokenContract) IsPaused(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.IsPaused()
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

func (c RegulatedTokenContract) GetRoleMembers(opts *bind.CallOpts, roleNumber byte) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetRoleMembers(roleNumber)
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

func (c RegulatedTokenContract) GetRoleMemberCount(opts *bind.CallOpts, roleNumber byte) (uint64, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetRoleMemberCount(roleNumber)
	if err != nil {
		return *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), err
	}

	var (
		r0 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(uint64), err
	}
	return r0, nil
}

func (c RegulatedTokenContract) GetRoleMember(opts *bind.CallOpts, roleNumber byte, index uint64) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetRoleMember(roleNumber, index)
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

func (c RegulatedTokenContract) GetAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetAdmin()
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

func (c RegulatedTokenContract) GetMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetMinters()
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

func (c RegulatedTokenContract) GetBridgeMintersOrBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetBridgeMintersOrBurners()
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

func (c RegulatedTokenContract) GetBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetBurners()
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

func (c RegulatedTokenContract) GetFreezers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetFreezers()
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

func (c RegulatedTokenContract) GetUnfreezers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetUnfreezers()
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

func (c RegulatedTokenContract) GetPausers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetPausers()
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

func (c RegulatedTokenContract) GetUnpausers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetUnpausers()
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

func (c RegulatedTokenContract) GetRecoveryManagers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetRecoveryManagers()
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

func (c RegulatedTokenContract) GetPendingAdmin(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetPendingAdmin()
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

func (c RegulatedTokenContract) IsFrozen(opts *bind.CallOpts, account aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.IsFrozen(account)
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

func (c RegulatedTokenContract) GetAllFrozenAccounts(opts *bind.CallOpts, startKey aptos.AccountAddress, maxCount uint64) ([]aptos.AccountAddress, aptos.AccountAddress, bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GetAllFrozenAccounts(startKey, maxCount)
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

func (c RegulatedTokenContract) HasRole(opts *bind.CallOpts, account aptos.AccountAddress, role byte) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.HasRole(account, role)
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

func (c RegulatedTokenContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Owner()
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

func (c RegulatedTokenContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.HasPendingTransfer()
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

func (c RegulatedTokenContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.PendingTransferFrom()
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

func (c RegulatedTokenContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.PendingTransferTo()
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

func (c RegulatedTokenContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.PendingTransferAccepted()
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

func (c RegulatedTokenContract) Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Initialize(maxSupply, name, symbol, decimals, icon, project)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Mint(to, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Burn(from, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) GrantRole(opts *bind.TransactOpts, roleNumber byte, account aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.GrantRole(roleNumber, account)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) RevokeRole(opts *bind.TransactOpts, roleNumber byte, account aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.RevokeRole(roleNumber, account)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) FreezeAccounts(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.FreezeAccounts(accounts)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) FreezeAccount(opts *bind.TransactOpts, account aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.FreezeAccount(account)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) UnfreezeAccounts(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.UnfreezeAccounts(accounts)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) UnfreezeAccount(opts *bind.TransactOpts, account aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.UnfreezeAccount(account)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) ApplyRoleUpdates(opts *bind.TransactOpts, roleNumber byte, addressesToRemove []aptos.AccountAddress, addressesToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.ApplyRoleUpdates(roleNumber, addressesToRemove, addressesToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) Pause(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Pause()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) Unpause(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.Unpause()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) BatchBurnFrozenFunds(opts *bind.TransactOpts, accounts []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.BatchBurnFrozenFunds(accounts)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) BurnFrozenFunds(opts *bind.TransactOpts, from aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.BurnFrozenFunds(from)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) RecoverFrozenFunds(opts *bind.TransactOpts, from aptos.AccountAddress, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.RecoverFrozenFunds(from, to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) BatchRecoverFrozenFunds(opts *bind.TransactOpts, accounts []aptos.AccountAddress, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.BatchRecoverFrozenFunds(accounts, to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) TransferAdmin(opts *bind.TransactOpts, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TransferAdmin(newAdmin)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) AcceptAdmin(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.AcceptAdmin()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) RecoverTokens(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.RecoverTokens(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegulatedTokenContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.regulatedTokenEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type regulatedTokenEncoder struct {
	*bind.BoundContract
}

func (c regulatedTokenEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenStateObject() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_object", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) Admin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("admin", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) PendingAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_admin", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_address", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) IsPaused() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_paused", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetRoleMembers(roleNumber byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_role_members", nil, []string{
		"u8",
	}, []any{
		roleNumber,
	})
}

func (c regulatedTokenEncoder) GetRoleMemberCount(roleNumber byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_role_member_count", nil, []string{
		"u8",
	}, []any{
		roleNumber,
	})
}

func (c regulatedTokenEncoder) GetRoleMember(roleNumber byte, index uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_role_member", nil, []string{
		"u8",
		"u64",
	}, []any{
		roleNumber,
		index,
	})
}

func (c regulatedTokenEncoder) GetAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_admin", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_minters", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetBridgeMintersOrBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_bridge_minters_or_burners", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_burners", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetFreezers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_freezers", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetUnfreezers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_unfreezers", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetPausers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pausers", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetUnpausers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_unpausers", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetRecoveryManagers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_recovery_managers", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) GetPendingAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_pending_admin", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) IsFrozen(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_frozen", nil, []string{
		"address",
	}, []any{
		account,
	})
}

func (c regulatedTokenEncoder) GetAllFrozenAccounts(startKey aptos.AccountAddress, maxCount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_all_frozen_accounts", nil, []string{
		"address",
		"u64",
	}, []any{
		startKey,
		maxCount,
	})
}

func (c regulatedTokenEncoder) HasRole(account aptos.AccountAddress, role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_role", nil, []string{
		"address",
		"u8",
	}, []any{
		account,
		role,
	})
}

func (c regulatedTokenEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"0x1::option::Option<u128>",
		"0x1::string::String",
		"0x1::string::String",
		"u8",
		"0x1::string::String",
		"0x1::string::String",
	}, []any{
		maxSupply,
		name,
		symbol,
		decimals,
		icon,
		project,
	})
}

func (c regulatedTokenEncoder) Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mint", nil, []string{
		"address",
		"u64",
	}, []any{
		to,
		amount,
	})
}

func (c regulatedTokenEncoder) Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("burn", nil, []string{
		"address",
		"u64",
	}, []any{
		from,
		amount,
	})
}

func (c regulatedTokenEncoder) GrantRole(roleNumber byte, account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("grant_role", nil, []string{
		"u8",
		"address",
	}, []any{
		roleNumber,
		account,
	})
}

func (c regulatedTokenEncoder) RevokeRole(roleNumber byte, account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("revoke_role", nil, []string{
		"u8",
		"address",
	}, []any{
		roleNumber,
		account,
	})
}

func (c regulatedTokenEncoder) FreezeAccounts(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("freeze_accounts", nil, []string{
		"vector<address>",
	}, []any{
		accounts,
	})
}

func (c regulatedTokenEncoder) FreezeAccount(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("freeze_account", nil, []string{
		"address",
	}, []any{
		account,
	})
}

func (c regulatedTokenEncoder) UnfreezeAccounts(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("unfreeze_accounts", nil, []string{
		"vector<address>",
	}, []any{
		accounts,
	})
}

func (c regulatedTokenEncoder) UnfreezeAccount(account aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("unfreeze_account", nil, []string{
		"address",
	}, []any{
		account,
	})
}

func (c regulatedTokenEncoder) ApplyRoleUpdates(roleNumber byte, addressesToRemove []aptos.AccountAddress, addressesToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_role_updates", nil, []string{
		"u8",
		"vector<address>",
		"vector<address>",
	}, []any{
		roleNumber,
		addressesToRemove,
		addressesToAdd,
	})
}

func (c regulatedTokenEncoder) Pause() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pause", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) Unpause() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("unpause", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) BatchBurnFrozenFunds(accounts []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("batch_burn_frozen_funds", nil, []string{
		"vector<address>",
	}, []any{
		accounts,
	})
}

func (c regulatedTokenEncoder) BurnFrozenFunds(from aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("burn_frozen_funds", nil, []string{
		"address",
	}, []any{
		from,
	})
}

func (c regulatedTokenEncoder) RecoverFrozenFunds(from aptos.AccountAddress, to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("recover_frozen_funds", nil, []string{
		"address",
		"address",
	}, []any{
		from,
		to,
	})
}

func (c regulatedTokenEncoder) BatchRecoverFrozenFunds(accounts []aptos.AccountAddress, to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("batch_recover_frozen_funds", nil, []string{
		"vector<address>",
		"address",
	}, []any{
		accounts,
		to,
	})
}

func (c regulatedTokenEncoder) TransferAdmin(newAdmin aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_admin", nil, []string{
		"address",
	}, []any{
		newAdmin,
	})
}

func (c regulatedTokenEncoder) AcceptAdmin() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_admin", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) RecoverTokens(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("recover_tokens", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c regulatedTokenEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c regulatedTokenEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c regulatedTokenEncoder) TokenStateObjectInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_object_internal", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address_internal", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) TokenMetadataFromStateObj(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata_from_state_obj", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) TokenMetadataInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata_internal", nil, []string{}, []any{})
}

func (c regulatedTokenEncoder) AssertPauser(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_pauser", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertUnpauser(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_unpauser", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertFreezer(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_freezer", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertUnfreezer(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_unfreezer", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertRecoveryRole(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_recovery_role", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertBridgeMinterOrBurner(stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_bridge_minter_or_burner", nil, []string{
		"address",
	}, []any{
		stateObj,
	})
}

func (c regulatedTokenEncoder) AssertBurnerAndGetType(burner aptos.AccountAddress, stateObj aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_burner_and_get_type", nil, []string{
		"address",
		"address",
	}, []any{
		burner,
		stateObj,
	})
}
