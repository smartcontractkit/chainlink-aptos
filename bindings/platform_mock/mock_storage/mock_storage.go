// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mock_storage

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

type MockStorageInterface interface {
	IsRegistered(opts *bind.CallOpts, receiver aptos.AccountAddress) (bool, error)
	ParseReportMetadata(opts *bind.CallOpts, metadata []byte) (ReportMetadata, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MockStorageEncoder
}

type MockStorageEncoder interface {
	IsRegistered(receiver aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ParseReportMetadata(metadata []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Insert(receiver aptos.AccountAddress, callbackMetadata []byte, callbackData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StorageExists(objAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StorageAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"platform_mock","module":"mock_storage","name":"insert","parameters":[{"name":"receiver","type":"address"},{"name":"callback_metadata","type":"vector\u003cu8\u003e"},{"name":"callback_data","type":"vector\u003cu8\u003e"}]},{"package":"platform_mock","module":"mock_storage","name":"storage_address","parameters":null},{"package":"platform_mock","module":"mock_storage","name":"storage_exists","parameters":[{"name":"obj_address","type":"address"}]}]`

func NewMockStorage(address aptos.AccountAddress, client aptos.AptosRpcClient) MockStorageInterface {
	contract := bind.NewBoundContract(address, "platform_mock", "mock_storage", client)
	return MockStorageContract{
		BoundContract:      contract,
		mockStorageEncoder: mockStorageEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_UNKNOWN_RECEIVER        uint64 = 1
	E_INVALID_METADATA_LENGTH uint64 = 2
)

// Structs

type Entry struct {
	Metadata bind.StdObject `move:"aptos_framework::object::Object"`
}

type Dispatcher struct {
}

type Storage struct {
	Metadata []byte `move:"vector<u8>"`
	Data     []byte `move:"vector<u8>"`
}

type ReportMetadata struct {
	WorkflowCid   []byte `move:"vector<u8>"`
	WorkflowName  []byte `move:"vector<u8>"`
	WorkflowOwner []byte `move:"vector<u8>"`
	ReportId      []byte `move:"vector<u8>"`
}

type MockStorageContract struct {
	*bind.BoundContract
	mockStorageEncoder
}

var _ MockStorageInterface = MockStorageContract{}

func (c MockStorageContract) Encoder() MockStorageEncoder {
	return c.mockStorageEncoder
}

// View Functions

func (c MockStorageContract) IsRegistered(opts *bind.CallOpts, receiver aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.mockStorageEncoder.IsRegistered(receiver)
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

func (c MockStorageContract) ParseReportMetadata(opts *bind.CallOpts, metadata []byte) (ReportMetadata, error) {
	module, function, typeTags, args, err := c.mockStorageEncoder.ParseReportMetadata(metadata)
	if err != nil {
		return *new(ReportMetadata), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(ReportMetadata), err
	}

	var (
		r0 ReportMetadata
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(ReportMetadata), err
	}
	return r0, nil
}

// Entry Functions

// Encoder
type mockStorageEncoder struct {
	*bind.BoundContract
}

func (c mockStorageEncoder) IsRegistered(receiver aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_registered", nil, []string{
		"address",
	}, []any{
		receiver,
	})
}

func (c mockStorageEncoder) ParseReportMetadata(metadata []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("parse_report_metadata", nil, []string{
		"vector<u8>",
	}, []any{
		metadata,
	})
}

func (c mockStorageEncoder) Insert(receiver aptos.AccountAddress, callbackMetadata []byte, callbackData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("insert", nil, []string{
		"address",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		receiver,
		callbackMetadata,
		callbackData,
	})
}

func (c mockStorageEncoder) StorageExists(objAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("storage_exists", nil, []string{
		"address",
	}, []any{
		objAddress,
	})
}

func (c mockStorageEncoder) StorageAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("storage_address", nil, []string{}, []any{})
}
