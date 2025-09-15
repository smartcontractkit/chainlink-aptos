// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_auth

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

type AuthInterface interface {
	GetAllowedOnramps(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	GetAllowedOfframps(opts *bind.CallOpts) ([]aptos.AccountAddress, error)
	IsOnrampAllowed(opts *bind.CallOpts, onrampAddress aptos.AccountAddress) (bool, error)
	IsOfframpAllowed(opts *bind.CallOpts, offrampAddress aptos.AccountAddress) (bool, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	ApplyAllowedOnrampUpdates(opts *bind.TransactOpts, onrampsToRemove []aptos.AccountAddress, onrampsToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyAllowedOfframpUpdates(opts *bind.TransactOpts, offrampsToRemove []aptos.AccountAddress, offrampsToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() AuthEncoder
}

type AuthEncoder interface {
	GetAllowedOnramps() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedOfframps() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsOnrampAllowed(onrampAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsOfframpAllowed(offrampAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedOnrampUpdates(onrampsToRemove []aptos.AccountAddress, onrampsToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplyAllowedOfframpUpdates(offrampsToRemove []aptos.AccountAddress, offrampsToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsAllowedOnramp(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertIsAllowedOfframp(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertOnlyOwner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"auth","name":"accept_ownership","parameters":null},{"package":"ccip","module":"auth","name":"apply_allowed_offramp_updates","parameters":[{"name":"offramps_to_remove","type":"vector\u003caddress\u003e"},{"name":"offramps_to_add","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"auth","name":"apply_allowed_onramp_updates","parameters":[{"name":"onramps_to_remove","type":"vector\u003caddress\u003e"},{"name":"onramps_to_add","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"auth","name":"assert_is_allowed_offramp","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"assert_is_allowed_onramp","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"assert_only_owner","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"auth","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip","module":"auth","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"auth","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip","module":"auth","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewAuth(address aptos.AccountAddress, client aptos.AptosRpcClient) AuthInterface {
	contract := bind.NewBoundContract(address, "ccip", "auth", client)
	return AuthContract{
		BoundContract: contract,
		authEncoder:   authEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_UNKNOWN_FUNCTION    uint64 = 1
	E_NOT_ALLOWED_ONRAMP  uint64 = 2
	E_NOT_ALLOWED_OFFRAMP uint64 = 3
	E_NOT_OWNER_OR_CCIP   uint64 = 4
)

// Structs

type AuthState struct {
}

type McmsCallback struct {
}

type AuthContract struct {
	*bind.BoundContract
	authEncoder
}

var _ AuthInterface = AuthContract{}

func (c AuthContract) Encoder() AuthEncoder {
	return c.authEncoder
}

// View Functions

func (c AuthContract) GetAllowedOnramps(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.GetAllowedOnramps()
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

func (c AuthContract) GetAllowedOfframps(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.GetAllowedOfframps()
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

func (c AuthContract) IsOnrampAllowed(opts *bind.CallOpts, onrampAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.authEncoder.IsOnrampAllowed(onrampAddress)
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

func (c AuthContract) IsOfframpAllowed(opts *bind.CallOpts, offrampAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.authEncoder.IsOfframpAllowed(offrampAddress)
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

func (c AuthContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.Owner()
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

func (c AuthContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.authEncoder.HasPendingTransfer()
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

func (c AuthContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.PendingTransferFrom()
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

func (c AuthContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.authEncoder.PendingTransferTo()
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

func (c AuthContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.authEncoder.PendingTransferAccepted()
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

func (c AuthContract) ApplyAllowedOnrampUpdates(opts *bind.TransactOpts, onrampsToRemove []aptos.AccountAddress, onrampsToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.ApplyAllowedOnrampUpdates(onrampsToRemove, onrampsToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) ApplyAllowedOfframpUpdates(opts *bind.TransactOpts, offrampsToRemove []aptos.AccountAddress, offrampsToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.ApplyAllowedOfframpUpdates(offrampsToRemove, offrampsToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c AuthContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.authEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type authEncoder struct {
	*bind.BoundContract
}

func (c authEncoder) GetAllowedOnramps() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_onramps", nil, []string{}, []any{})
}

func (c authEncoder) GetAllowedOfframps() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_offramps", nil, []string{}, []any{})
}

func (c authEncoder) IsOnrampAllowed(onrampAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_onramp_allowed", nil, []string{
		"address",
	}, []any{
		onrampAddress,
	})
}

func (c authEncoder) IsOfframpAllowed(offrampAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_offramp_allowed", nil, []string{
		"address",
	}, []any{
		offrampAddress,
	})
}

func (c authEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c authEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c authEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c authEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c authEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c authEncoder) ApplyAllowedOnrampUpdates(onrampsToRemove []aptos.AccountAddress, onrampsToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_onramp_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		onrampsToRemove,
		onrampsToAdd,
	})
}

func (c authEncoder) ApplyAllowedOfframpUpdates(offrampsToRemove []aptos.AccountAddress, offrampsToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_allowed_offramp_updates", nil, []string{
		"vector<address>",
		"vector<address>",
	}, []any{
		offrampsToRemove,
		offrampsToAdd,
	})
}

func (c authEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c authEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c authEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c authEncoder) AssertIsAllowedOnramp(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_allowed_onramp", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c authEncoder) AssertIsAllowedOfframp(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_is_allowed_offramp", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c authEncoder) AssertOnlyOwner(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_only_owner", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c authEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c authEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}
