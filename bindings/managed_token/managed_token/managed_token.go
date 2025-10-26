// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_managed_token

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

type ManagedTokenInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetAllowedMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetAllowedBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	IsMinterAllowed(opts *bind.CallOpts, minter aptos.AccountAddress) (bool, error)
	IsBurnerAllowed(opts *bind.CallOpts, burner aptos.AccountAddress) (bool, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error)
	ApplyAllowedMinterUpdates(opts *bind.TransactOpts, mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyAllowedBurnerUpdates(opts *bind.TransactOpts, burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() ManagedTokenEncoder
}

type ManagedTokenEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsMinterAllowed(minter aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsBurnerAllowed(burner aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedMinterUpdates(mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedBurnerUpdates(burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"managed_token","module":"managed_token","name":"accept_ownership","parameters":null},{"package":"managed_token","module":"managed_token","name":"apply_allowed_burner_updates","parameters":[{"name":"burners_to_remove","type":"vector\u003caddress\u003e"},{"name":"burners_to_add","type":"vector\u003caddress\u003e"}]},{"package":"managed_token","module":"managed_token","name":"apply_allowed_minter_updates","parameters":[{"name":"minters_to_remove","type":"vector\u003caddress\u003e"},{"name":"minters_to_add","type":"vector\u003caddress\u003e"}]},{"package":"managed_token","module":"managed_token","name":"burn","parameters":[{"name":"from","type":"address"},{"name":"amount","type":"u64"}]},{"package":"managed_token","module":"managed_token","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"managed_token","module":"managed_token","name":"initialize","parameters":[{"name":"max_supply","type":"0x1::option::Option\u003cu128\u003e"},{"name":"name","type":"0x1::string::String"},{"name":"symbol","type":"0x1::string::String"},{"name":"decimals","type":"u8"},{"name":"icon","type":"0x1::string::String"},{"name":"project","type":"0x1::string::String"}]},{"package":"managed_token","module":"managed_token","name":"mint","parameters":[{"name":"to","type":"address"},{"name":"amount","type":"u64"}]},{"package":"managed_token","module":"managed_token","name":"token_state_address_internal","parameters":null},{"package":"managed_token","module":"managed_token","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewManagedToken(address aptos.AccountAddress, client aptos.AptosRpcClient) ManagedTokenInterface {
	contract := bind.NewBoundContract(address, "managed_token", "managed_token", client)
	return ManagedTokenContract{
		BoundContract:       contract,
		managedTokenEncoder: managedTokenEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_NOT_PUBLISHER                              uint64 = 1
	E_NOT_ALLOWED_MINTER                         uint64 = 2
	E_NOT_ALLOWED_BURNER                         uint64 = 3
	E_TOKEN_NOT_INITIALIZED                      uint64 = 4
	E_TOKEN_ALREADY_INITIALIZED                  uint64 = 5
	E_TOKEN_STATE_DEPLOYMENT_ALREADY_INITIALIZED uint64 = 6
)

// Structs

type TokenStateDeployment struct {
}

type TokenState struct {
	Token bind.StdObject `move:"aptos_framework::object::Object"`
}

type TokenMetadataRefs struct {
}

type Initialize struct {
	Publisher aptos.AccountAddress `move:"address"`
	Token     bind.StdObject       `move:"aptos_framework::object::Object"`
	MaxSupply **big.Int            `move:"0x1::option::Option<u128>"`
	Decimals  byte                 `move:"u8"`
	Icon      string               `move:"0x1::string::String"`
	Project   string               `move:"0x1::string::String"`
}

type Mint struct {
	Minter aptos.AccountAddress `move:"address"`
	To     aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type Burn struct {
	Burner aptos.AccountAddress `move:"address"`
	From   aptos.AccountAddress `move:"address"`
	Amount uint64               `move:"u64"`
}

type ManagedTokenContract struct {
	*bind.BoundContract
	managedTokenEncoder
}

var _ ManagedTokenInterface = ManagedTokenContract{}

func (c ManagedTokenContract) Encoder() ManagedTokenEncoder {
	return c.managedTokenEncoder
}

// View Functions

func (c ManagedTokenContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.TypeAndVersion()
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

func (c ManagedTokenContract) TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.TokenStateAddress()
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

func (c ManagedTokenContract) TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.TokenMetadata()
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

func (c ManagedTokenContract) GetAllowedMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.GetAllowedMinters()
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

func (c ManagedTokenContract) GetAllowedBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.GetAllowedBurners()
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

func (c ManagedTokenContract) IsMinterAllowed(opts *bind.CallOpts, minter aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.IsMinterAllowed(minter)
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

func (c ManagedTokenContract) IsBurnerAllowed(opts *bind.CallOpts, burner aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.IsBurnerAllowed(burner)
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

func (c ManagedTokenContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.Owner()
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

func (c ManagedTokenContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.HasPendingTransfer()
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

func (c ManagedTokenContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.PendingTransferFrom()
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

func (c ManagedTokenContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.PendingTransferTo()
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

func (c ManagedTokenContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.PendingTransferAccepted()
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

func (c ManagedTokenContract) Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.Initialize(maxSupply, name, symbol, decimals, icon, project)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) ApplyAllowedMinterUpdates(opts *bind.TransactOpts, mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.ApplyAllowedMinterUpdates(mintersToRemove, mintersToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) ApplyAllowedBurnerUpdates(opts *bind.TransactOpts, burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.ApplyAllowedBurnerUpdates(burnersToRemove, burnersToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.Mint(to, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.Burn(from, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ManagedTokenContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.managedTokenEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type managedTokenEncoder struct {
	*bind.BoundContract
}

func (c managedTokenEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c managedTokenEncoder) TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address", nil, []string{}, []any{})
}

func (c managedTokenEncoder) TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata", nil, []string{}, []any{})
}

func (c managedTokenEncoder) GetAllowedMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_minters", nil, []string{}, []any{})
}

func (c managedTokenEncoder) GetAllowedBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_burners", nil, []string{}, []any{})
}

func (c managedTokenEncoder) IsMinterAllowed(minter aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_minter_allowed", nil, []string{
		"address",
	}, []any{
		minter,
	})
}

func (c managedTokenEncoder) IsBurnerAllowed(burner aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_burner_allowed", nil, []string{
		"address",
	}, []any{
		burner,
	})
}

func (c managedTokenEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c managedTokenEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c managedTokenEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c managedTokenEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c managedTokenEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c managedTokenEncoder) Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c managedTokenEncoder) ApplyAllowedMinterUpdates(mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_minter_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		mintersToRemove,
		mintersToAdd,
	})
}

func (c managedTokenEncoder) ApplyAllowedBurnerUpdates(burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_burner_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		burnersToRemove,
		burnersToAdd,
	})
}

func (c managedTokenEncoder) Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mint", nil, []string{
		"address",
		"u64",
	}, []any{
		to,
		amount,
	})
}

func (c managedTokenEncoder) Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("burn", nil, []string{
		"address",
		"u64",
	}, []any{
		from,
		amount,
	})
}

func (c managedTokenEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c managedTokenEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c managedTokenEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c managedTokenEncoder) TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address_internal", nil, []string{}, []any{})
}
