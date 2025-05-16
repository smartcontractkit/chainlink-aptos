// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_link_token

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

type LinkTokenInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetAllowedMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetAllowedBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	IsMinterAllowed(opts *bind.CallOpts, minter aptos.AccountAddress) (bool, error)
	IsBurnerAllowed(opts *bind.CallOpts, burner aptos.AccountAddress) (bool, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)

	Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error)
	ApplyAllowedMinterUpdates(opts *bind.TransactOpts, mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyAllowedBurnerUpdates(opts *bind.TransactOpts, burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() LinkTokenEncoder
}

type LinkTokenEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsMinterAllowed(minter aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsBurnerAllowed(burner aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedMinterUpdates(mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedBurnerUpdates(burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TokenMetadataInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsAllowedMinter(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsAllowedBurner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"link","module":"link_token","name":"accept_ownership","parameters":null},{"package":"link","module":"link_token","name":"apply_allowed_burner_updates","parameters":[{"name":"burners_to_remove","type":"vector\u003caddress\u003e"},{"name":"burners_to_add","type":"vector\u003caddress\u003e"}]},{"package":"link","module":"link_token","name":"apply_allowed_minter_updates","parameters":[{"name":"minters_to_remove","type":"vector\u003caddress\u003e"},{"name":"minters_to_add","type":"vector\u003caddress\u003e"}]},{"package":"link","module":"link_token","name":"assert_is_allowed_burner","parameters":[{"name":"caller","type":"address"}]},{"package":"link","module":"link_token","name":"assert_is_allowed_minter","parameters":[{"name":"caller","type":"address"}]},{"package":"link","module":"link_token","name":"burn","parameters":[{"name":"from","type":"address"},{"name":"amount","type":"u64"}]},{"package":"link","module":"link_token","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"link","module":"link_token","name":"initialize","parameters":[{"name":"max_supply","type":"0x1::option::Option\u003cu128\u003e"},{"name":"name","type":"0x1::string::String"},{"name":"symbol","type":"0x1::string::String"},{"name":"decimals","type":"u8"},{"name":"icon","type":"0x1::string::String"},{"name":"project","type":"0x1::string::String"}]},{"package":"link","module":"link_token","name":"mint","parameters":[{"name":"to","type":"address"},{"name":"amount","type":"u64"}]},{"package":"link","module":"link_token","name":"token_metadata_internal","parameters":null},{"package":"link","module":"link_token","name":"token_state_address_internal","parameters":null},{"package":"link","module":"link_token","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewLinkToken(address aptos.AccountAddress, client aptos.AptosRpcClient) LinkTokenInterface {
	contract := bind.NewBoundContract(address, "link", "mcms_token_registrar", client)
	return LinkTokenContract{
		BoundContract:    contract,
		linkTokenEncoder: linkTokenEncoder{BoundContract: contract},
	}
}

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

type LinkTokenContract struct {
	*bind.BoundContract
	linkTokenEncoder
}

var _ LinkTokenInterface = LinkTokenContract{}

func (c LinkTokenContract) Encoder() LinkTokenEncoder {
	return c.linkTokenEncoder
}

// View Functions

func (c LinkTokenContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.TypeAndVersion()
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

func (c LinkTokenContract) TokenStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.TokenStateAddress()
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

func (c LinkTokenContract) TokenMetadata(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.TokenMetadata()
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

func (c LinkTokenContract) GetAllowedMinters(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.GetAllowedMinters()
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

func (c LinkTokenContract) GetAllowedBurners(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.GetAllowedBurners()
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

func (c LinkTokenContract) IsMinterAllowed(opts *bind.CallOpts, minter aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.IsMinterAllowed(minter)
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

func (c LinkTokenContract) IsBurnerAllowed(opts *bind.CallOpts, burner aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.IsBurnerAllowed(burner)
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

func (c LinkTokenContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.Owner()
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

// Entry Functions

func (c LinkTokenContract) Initialize(opts *bind.TransactOpts, maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.Initialize(maxSupply, name, symbol, decimals, icon, project)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) ApplyAllowedMinterUpdates(opts *bind.TransactOpts, mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.ApplyAllowedMinterUpdates(mintersToRemove, mintersToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) ApplyAllowedBurnerUpdates(opts *bind.TransactOpts, burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.ApplyAllowedBurnerUpdates(burnersToRemove, burnersToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) Mint(opts *bind.TransactOpts, to aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.Mint(to, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) Burn(opts *bind.TransactOpts, from aptos.AccountAddress, amount uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.Burn(from, amount)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LinkTokenContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.linkTokenEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type linkTokenEncoder struct {
	*bind.BoundContract
}

func (c linkTokenEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c linkTokenEncoder) TokenStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address", nil, []string{}, []any{})
}

func (c linkTokenEncoder) TokenMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata", nil, []string{}, []any{})
}

func (c linkTokenEncoder) GetAllowedMinters() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_minters", nil, []string{}, []any{})
}

func (c linkTokenEncoder) GetAllowedBurners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_burners", nil, []string{}, []any{})
}

func (c linkTokenEncoder) IsMinterAllowed(minter aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_minter_allowed", nil, []string{
		"address",
	}, []any{
		minter,
	})
}

func (c linkTokenEncoder) IsBurnerAllowed(burner aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_burner_allowed", nil, []string{
		"address",
	}, []any{
		burner,
	})
}

func (c linkTokenEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c linkTokenEncoder) Initialize(maxSupply **big.Int, name string, symbol string, decimals byte, icon string, project string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c linkTokenEncoder) ApplyAllowedMinterUpdates(mintersToRemove []aptos.AccountAddress, mintersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_minter_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		mintersToRemove,
		mintersToAdd,
	})
}

func (c linkTokenEncoder) ApplyAllowedBurnerUpdates(burnersToRemove []aptos.AccountAddress, burnersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_burner_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		burnersToRemove,
		burnersToAdd,
	})
}

func (c linkTokenEncoder) Mint(to aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mint", nil, []string{
		"address",
		"u64",
	}, []any{
		to,
		amount,
	})
}

func (c linkTokenEncoder) Burn(from aptos.AccountAddress, amount uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("burn", nil, []string{
		"address",
		"u64",
	}, []any{
		from,
		amount,
	})
}

func (c linkTokenEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c linkTokenEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c linkTokenEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c linkTokenEncoder) TokenStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_state_address_internal", nil, []string{}, []any{})
}

func (c linkTokenEncoder) TokenMetadataInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("token_metadata_internal", nil, []string{}, []any{})
}

func (c linkTokenEncoder) AssertIsAllowedMinter(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_allowed_minter", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c linkTokenEncoder) AssertIsAllowedBurner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_allowed_burner", nil, []string{
		"address",
	}, []any{
		caller,
	})
}
