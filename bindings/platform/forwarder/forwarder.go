// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_forwarder

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

type ForwarderInterface interface {
	GetTransmissionState(opts *bind.CallOpts, receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bool, error)
	GetTransmitter(opts *bind.CallOpts, receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (*aptos.AccountAddress, error)
	GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetConfig(opts *bind.CallOpts, donId uint32, configVersion uint32) (Config, error)

	SetConfig(opts *bind.TransactOpts, donId uint32, configVersion uint32, f byte, oracles [][]byte) (*api.PendingTransaction, error)
	ClearConfig(opts *bind.TransactOpts, donId uint32, configVersion uint32) (*api.PendingTransaction, error)
	Report(opts *bind.TransactOpts, receiver aptos.AccountAddress, rawReport []byte, signatures [][]byte) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() ForwarderEncoder
}

type ForwarderEncoder interface {
	GetTransmissionState(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetTransmitter(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetConfig(donId uint32, configVersion uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetConfig(donId uint32, configVersion uint32, f byte, oracles [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ClearConfig(donId uint32, configVersion uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Report(receiver aptos.AccountAddress, rawReport []byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SignatureFromBytes(bytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransmissionId(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Dispatch(receiver aptos.AccountAddress, metadata []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ToU16be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ToU32be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ValidateAndProcessReport(receiver aptos.AccountAddress, rawReport []byte, signatures []Signature) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"platform","module":"forwarder","name":"accept_ownership","parameters":null},{"package":"platform","module":"forwarder","name":"clear_config","parameters":[{"name":"don_id","type":"u32"},{"name":"config_version","type":"u32"}]},{"package":"platform","module":"forwarder","name":"dispatch","parameters":[{"name":"receiver","type":"address"},{"name":"metadata","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"platform","module":"forwarder","name":"get_state_addr","parameters":null},{"package":"platform","module":"forwarder","name":"report","parameters":[{"name":"receiver","type":"address"},{"name":"raw_report","type":"vector\u003cu8\u003e"},{"name":"signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"platform","module":"forwarder","name":"set_config","parameters":[{"name":"don_id","type":"u32"},{"name":"config_version","type":"u32"},{"name":"f","type":"u8"},{"name":"oracles","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"platform","module":"forwarder","name":"signature_from_bytes","parameters":[{"name":"bytes","type":"vector\u003cu8\u003e"}]},{"package":"platform","module":"forwarder","name":"to_u16be","parameters":[{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"platform","module":"forwarder","name":"to_u32be","parameters":[{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"platform","module":"forwarder","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"platform","module":"forwarder","name":"transmission_id","parameters":[{"name":"receiver","type":"address"},{"name":"workflow_execution_id","type":"vector\u003cu8\u003e"},{"name":"report_id","type":"u16"}]},{"package":"platform","module":"forwarder","name":"validate_and_process_report","parameters":[{"name":"receiver","type":"address"},{"name":"raw_report","type":"vector\u003cu8\u003e"},{"name":"signatures","type":"vector\u003cSignature\u003e"}]}]`

func NewForwarder(address aptos.AccountAddress, client aptos.AptosRpcClient) ForwarderInterface {
	contract := bind.NewBoundContract(address, "platform", "forwarder", client)
	return ForwarderContract{
		BoundContract:    contract,
		forwarderEncoder: forwarderEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_INVALID_DATA_LENGTH              uint64 = 1
	E_INVALID_SIGNER                   uint64 = 2
	E_DUPLICATE_SIGNER                 uint64 = 3
	E_INVALID_SIGNATURE_COUNT          uint64 = 4
	E_INVALID_SIGNATURE                uint64 = 5
	E_ALREADY_PROCESSED                uint64 = 6
	E_NOT_OWNER                        uint64 = 7
	E_MALFORMED_SIGNATURE              uint64 = 8
	E_FAULT_TOLERANCE_MUST_BE_POSITIVE uint64 = 9
	E_EXCESS_SIGNERS                   uint64 = 10
	E_INSUFFICIENT_SIGNERS             uint64 = 11
	E_CALLBACK_DATA_NOT_CONSUMED       uint64 = 12
	E_CANNOT_TRANSFER_TO_SELF          uint64 = 13
	E_NOT_PROPOSED_OWNER               uint64 = 14
	E_CONFIG_ID_NOT_FOUND              uint64 = 15
	E_INVALID_REPORT_VERSION           uint64 = 16
	MAX_ORACLES                        uint64 = 31
)

// Structs

type ConfigId struct {
	DonId         uint32 `move:"u32"`
	ConfigVersion uint32 `move:"u32"`
}

type State struct {
	OwnerAddress        aptos.AccountAddress `move:"address"`
	PendingOwnerAddress aptos.AccountAddress `move:"address"`
}

type Config struct {
	F byte `move:"u8"`
}

type ConfigSet struct {
	DonId         uint32   `move:"u32"`
	ConfigVersion uint32   `move:"u32"`
	F             byte     `move:"u8"`
	Signers       [][]byte `move:"vector<vector<u8>>"`
}

type ReportProcessed struct {
	Receiver            aptos.AccountAddress `move:"address"`
	WorkflowExecutionId []byte               `move:"vector<u8>"`
	ReportId            uint16               `move:"u16"`
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferred struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type Signature struct {
}

type OracleSet struct {
	DonId         uint32   `move:"u32"`
	ConfigVersion uint32   `move:"u32"`
	F             byte     `move:"u8"`
	Oracles       [][]byte `move:"vector<vector<u8>>"`
}

type ForwarderContract struct {
	*bind.BoundContract
	forwarderEncoder
}

var _ ForwarderInterface = ForwarderContract{}

func (c ForwarderContract) Encoder() ForwarderEncoder {
	return c.forwarderEncoder
}

// View Functions

func (c ForwarderContract) GetTransmissionState(opts *bind.CallOpts, receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bool, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.GetTransmissionState(receiver, workflowExecutionId, reportId)
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

func (c ForwarderContract) GetTransmitter(opts *bind.CallOpts, receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.GetTransmitter(receiver, workflowExecutionId, reportId)
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

func (c ForwarderContract) GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.GetOwner()
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

func (c ForwarderContract) GetConfig(opts *bind.CallOpts, donId uint32, configVersion uint32) (Config, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.GetConfig(donId, configVersion)
	if err != nil {
		return *new(Config), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(Config), err
	}

	var (
		r0 Config
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(Config), err
	}
	return r0, nil
}

// Entry Functions

func (c ForwarderContract) SetConfig(opts *bind.TransactOpts, donId uint32, configVersion uint32, f byte, oracles [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.SetConfig(donId, configVersion, f, oracles)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ForwarderContract) ClearConfig(opts *bind.TransactOpts, donId uint32, configVersion uint32) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.ClearConfig(donId, configVersion)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ForwarderContract) Report(opts *bind.TransactOpts, receiver aptos.AccountAddress, rawReport []byte, signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.Report(receiver, rawReport, signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ForwarderContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c ForwarderContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.forwarderEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type forwarderEncoder struct {
	*bind.BoundContract
}

func (c forwarderEncoder) GetTransmissionState(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_transmission_state", nil, []string{
		"address",
		"vector<u8>",
		"u16",
	}, []any{
		receiver,
		workflowExecutionId,
		reportId,
	})
}

func (c forwarderEncoder) GetTransmitter(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_transmitter", nil, []string{
		"address",
		"vector<u8>",
		"u16",
	}, []any{
		receiver,
		workflowExecutionId,
		reportId,
	})
}

func (c forwarderEncoder) GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_owner", nil, []string{}, []any{})
}

func (c forwarderEncoder) GetConfig(donId uint32, configVersion uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_config", nil, []string{
		"u32",
		"u32",
	}, []any{
		donId,
		configVersion,
	})
}

func (c forwarderEncoder) SetConfig(donId uint32, configVersion uint32, f byte, oracles [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_config", nil, []string{
		"u32",
		"u32",
		"u8",
		"vector<vector<u8>>",
	}, []any{
		donId,
		configVersion,
		f,
		oracles,
	})
}

func (c forwarderEncoder) ClearConfig(donId uint32, configVersion uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("clear_config", nil, []string{
		"u32",
		"u32",
	}, []any{
		donId,
		configVersion,
	})
}

func (c forwarderEncoder) Report(receiver aptos.AccountAddress, rawReport []byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("report", nil, []string{
		"address",
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		receiver,
		rawReport,
		signatures,
	})
}

func (c forwarderEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c forwarderEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c forwarderEncoder) GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_addr", nil, []string{}, []any{})
}

func (c forwarderEncoder) SignatureFromBytes(bytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("signature_from_bytes", nil, []string{
		"vector<u8>",
	}, []any{
		bytes,
	})
}

func (c forwarderEncoder) TransmissionId(receiver aptos.AccountAddress, workflowExecutionId []byte, reportId uint16) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transmission_id", nil, []string{
		"address",
		"vector<u8>",
		"u16",
	}, []any{
		receiver,
		workflowExecutionId,
		reportId,
	})
}

func (c forwarderEncoder) Dispatch(receiver aptos.AccountAddress, metadata []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("dispatch", nil, []string{
		"address",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		receiver,
		metadata,
		data,
	})
}

func (c forwarderEncoder) ToU16be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("to_u16be", nil, []string{
		"vector<u8>",
	}, []any{
		data,
	})
}

func (c forwarderEncoder) ToU32be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("to_u32be", nil, []string{
		"vector<u8>",
	}, []any{
		data,
	})
}

func (c forwarderEncoder) ValidateAndProcessReport(receiver aptos.AccountAddress, rawReport []byte, signatures []Signature) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("validate_and_process_report", nil, []string{
		"address",
		"vector<u8>",
		"vector<Signature>",
	}, []any{
		receiver,
		rawReport,
		signatures,
	})
}
