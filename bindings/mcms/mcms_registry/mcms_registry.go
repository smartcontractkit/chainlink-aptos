// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms_registry

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

type MCMSRegistryInterface interface {
	GetNewCodeObjectOwnerAddress(opts *bind.CallOpts, newOwnerSeed []byte) (aptos.AccountAddress, error)
	GetNewCodeObjectAddress(opts *bind.CallOpts, newOwnerSeed []byte) (aptos.AccountAddress, error)
	GetPreexistingCodeObjectOwnerAddress(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	GetRegisteredOwnerAddress(opts *bind.CallOpts, accountAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	IsOwnedCodeObject(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (bool, error)

	CreateOwnerForPreexistingCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	ExecuteCodeObjectTransfer(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSRegistryEncoder
}

type MCMSRegistryEncoder interface {
	GetNewCodeObjectOwnerAddress(newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetNewCodeObjectAddress(newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetPreexistingCodeObjectOwnerAddress(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRegisteredOwnerAddress(accountAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsOwnedCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CreateOwnerForPreexistingCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferCodeObject(objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteCodeObjectTransfer(objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StartDispatch(callbackAddress aptos.AccountAddress, callbackModuleName string, callbackFunction string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FinishDispatch(callbackAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_registry","name":"accept_code_object","parameters":[{"name":"object_address","type":"address"}]},{"package":"mcms","module":"mcms_registry","name":"create_owner_for_preexisting_code_object","parameters":[{"name":"object_address","type":"address"}]},{"package":"mcms","module":"mcms_registry","name":"execute_code_object_transfer","parameters":[{"name":"object_address","type":"address"},{"name":"new_owner_address","type":"address"}]},{"package":"mcms","module":"mcms_registry","name":"finish_dispatch","parameters":[{"name":"callback_address","type":"address"}]},{"package":"mcms","module":"mcms_registry","name":"start_dispatch","parameters":[{"name":"callback_address","type":"address"},{"name":"callback_module_name","type":"0x1::string::String"},{"name":"callback_function","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms_registry","name":"transfer_code_object","parameters":[{"name":"object_address","type":"address"},{"name":"new_owner_address","type":"address"}]}]`

func NewMCMSRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSRegistryInterface {
	contract := bind.NewBoundContract(address, "mcms", "mcms_registry", client)
	return MCMSRegistryContract{
		BoundContract:       contract,
		mcmsRegistryEncoder: mcmsRegistryEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_CALLBACK_PARAMS_ALREADY_EXISTS uint64 = 1
	E_MISSING_CALLBACK_PARAMS        uint64 = 2
	E_WRONG_PROOF_TYPE               uint64 = 3
	E_CALLBACK_PARAMS_NOT_CONSUMED   uint64 = 4
	E_PROOF_NOT_AT_ACCOUNT_ADDRESS   uint64 = 5
	E_PROOF_NOT_IN_MODULE            uint64 = 6
	E_MODULE_ALREADY_REGISTERED      uint64 = 7
	E_EMPTY_MODULE_NAME              uint64 = 8
	E_MODULE_NAME_TOO_LONG           uint64 = 9
	E_ADDRESS_NOT_REGISTERED         uint64 = 10
	E_INVALID_CODE_OBJECT            uint64 = 11
	E_OWNER_ALREADY_REGISTERED       uint64 = 12
	E_NOT_CODE_OBJECT_OWNER          uint64 = 13
	E_UNGATED_TRANSFER_DISABLED      uint64 = 14
	E_NO_PENDING_TRANSFER            uint64 = 15
	E_TRANSFER_ALREADY_ACCEPTED      uint64 = 16
	E_NEW_OWNER_MISMATCH             uint64 = 17
	E_TRANSFER_NOT_ACCEPTED          uint64 = 18
	E_NOT_PROPOSED_OWNER             uint64 = 19
	E_MODULE_NOT_REGISTERED          uint64 = 20
)

// Structs

type RegistryState struct {
}

type OwnerRegistration struct {
	OwnerSeed       []byte `move:"vector<u8>"`
	IsPreregistered bool   `move:"bool"`
}

type OwnerTransfers struct {
}

type RegisteredModule struct {
	DispatchMetadata bind.StdObject `move:"aptos_framework::object::Object"`
}

type PendingCodeObjectTransfer struct {
	To       aptos.AccountAddress `move:"address"`
	Accepted bool                 `move:"bool"`
}

type ExecutingCallbackParams struct {
	Function string `move:"0x1::string::String"`
	Data     []byte `move:"vector<u8>"`
}

type EntrypointRegistered struct {
	OwnerAddress   aptos.AccountAddress `move:"address"`
	AccountAddress aptos.AccountAddress `move:"address"`
	ModuleName     string               `move:"0x1::string::String"`
}

type CodeObjectTransferRequested struct {
	ObjectAddress    aptos.AccountAddress `move:"address"`
	MCMSOwnerAddress aptos.AccountAddress `move:"address"`
	NewOwnerAddress  aptos.AccountAddress `move:"address"`
}

type CodeObjectTransferAccepted struct {
	ObjectAddress    aptos.AccountAddress `move:"address"`
	MCMSOwnerAddress aptos.AccountAddress `move:"address"`
	NewOwnerAddress  aptos.AccountAddress `move:"address"`
}

type CodeObjectTransferred struct {
	ObjectAddress    aptos.AccountAddress `move:"address"`
	MCMSOwnerAddress aptos.AccountAddress `move:"address"`
	NewOwnerAddress  aptos.AccountAddress `move:"address"`
}

type OwnerCreatedForPreexistingObject struct {
	OwnerAddress  aptos.AccountAddress `move:"address"`
	ObjectAddress aptos.AccountAddress `move:"address"`
}

type OwnerCreatedForNewObject struct {
	OwnerAddress          aptos.AccountAddress `move:"address"`
	ExpectedObjectAddress aptos.AccountAddress `move:"address"`
}

type OwnerCreatedForEntrypoint struct {
	OwnerAddress           aptos.AccountAddress `move:"address"`
	AccountOrObjectAddress aptos.AccountAddress `move:"address"`
}

type MCMSRegistryContract struct {
	*bind.BoundContract
	mcmsRegistryEncoder
}

var _ MCMSRegistryInterface = MCMSRegistryContract{}

func (c MCMSRegistryContract) Encoder() MCMSRegistryEncoder {
	return c.mcmsRegistryEncoder
}

// View Functions

func (c MCMSRegistryContract) GetNewCodeObjectOwnerAddress(opts *bind.CallOpts, newOwnerSeed []byte) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.GetNewCodeObjectOwnerAddress(newOwnerSeed)
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

func (c MCMSRegistryContract) GetNewCodeObjectAddress(opts *bind.CallOpts, newOwnerSeed []byte) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.GetNewCodeObjectAddress(newOwnerSeed)
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

func (c MCMSRegistryContract) GetPreexistingCodeObjectOwnerAddress(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.GetPreexistingCodeObjectOwnerAddress(objectAddress)
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

func (c MCMSRegistryContract) GetRegisteredOwnerAddress(opts *bind.CallOpts, accountAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.GetRegisteredOwnerAddress(accountAddress)
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

func (c MCMSRegistryContract) IsOwnedCodeObject(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.IsOwnedCodeObject(objectAddress)
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

func (c MCMSRegistryContract) CreateOwnerForPreexistingCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.CreateOwnerForPreexistingCodeObject(objectAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSRegistryContract) TransferCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.TransferCodeObject(objectAddress, newOwnerAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSRegistryContract) AcceptCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.AcceptCodeObject(objectAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSRegistryContract) ExecuteCodeObjectTransfer(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsRegistryEncoder.ExecuteCodeObjectTransfer(objectAddress, newOwnerAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsRegistryEncoder struct {
	*bind.BoundContract
}

func (c mcmsRegistryEncoder) GetNewCodeObjectOwnerAddress(newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_new_code_object_owner_address", nil, []string{
		"vector<u8>",
	}, []any{
		newOwnerSeed,
	})
}

func (c mcmsRegistryEncoder) GetNewCodeObjectAddress(newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_new_code_object_address", nil, []string{
		"vector<u8>",
	}, []any{
		newOwnerSeed,
	})
}

func (c mcmsRegistryEncoder) GetPreexistingCodeObjectOwnerAddress(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_preexisting_code_object_owner_address", nil, []string{
		"address",
	}, []any{
		objectAddress,
	})
}

func (c mcmsRegistryEncoder) GetRegisteredOwnerAddress(accountAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_registered_owner_address", nil, []string{
		"address",
	}, []any{
		accountAddress,
	})
}

func (c mcmsRegistryEncoder) IsOwnedCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_owned_code_object", nil, []string{
		"address",
	}, []any{
		objectAddress,
	})
}

func (c mcmsRegistryEncoder) CreateOwnerForPreexistingCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("create_owner_for_preexisting_code_object", nil, []string{
		"address",
	}, []any{
		objectAddress,
	})
}

func (c mcmsRegistryEncoder) TransferCodeObject(objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_code_object", nil, []string{
		"address",
		"address",
	}, []any{
		objectAddress,
		newOwnerAddress,
	})
}

func (c mcmsRegistryEncoder) AcceptCodeObject(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_code_object", nil, []string{
		"address",
	}, []any{
		objectAddress,
	})
}

func (c mcmsRegistryEncoder) ExecuteCodeObjectTransfer(objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_code_object_transfer", nil, []string{
		"address",
		"address",
	}, []any{
		objectAddress,
		newOwnerAddress,
	})
}

func (c mcmsRegistryEncoder) StartDispatch(callbackAddress aptos.AccountAddress, callbackModuleName string, callbackFunction string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("start_dispatch", nil, []string{
		"address",
		"0x1::string::String",
		"0x1::string::String",
		"vector<u8>",
	}, []any{
		callbackAddress,
		callbackModuleName,
		callbackFunction,
		data,
	})
}

func (c mcmsRegistryEncoder) FinishDispatch(callbackAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("finish_dispatch", nil, []string{
		"address",
	}, []any{
		callbackAddress,
	})
}
