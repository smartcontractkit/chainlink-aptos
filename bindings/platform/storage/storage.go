// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_storage

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

type StorageInterface interface {
	ParseReportMetadata(opts *bind.CallOpts, metadata []byte) (ReportMetadata, error)

	MigrateToV2(opts *bind.TransactOpts, callbackAddresses []aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() StorageEncoder
}

type StorageEncoder interface {
	ParseReportMetadata(metadata []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MigrateToV2(callbackAddresses []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Insert(receiver aptos.AccountAddress, callbackMetadata []byte, callbackData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StorageExists(objAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StorageAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"platform","module":"storage","name":"insert","parameters":[{"name":"receiver","type":"address"},{"name":"callback_metadata","type":"vector\u003cu8\u003e"},{"name":"callback_data","type":"vector\u003cu8\u003e"}]},{"package":"platform","module":"storage","name":"migrate_to_v2","parameters":[{"name":"callback_addresses","type":"vector\u003caddress\u003e"}]},{"package":"platform","module":"storage","name":"storage_address","parameters":null},{"package":"platform","module":"storage","name":"storage_exists","parameters":[{"name":"obj_address","type":"address"}]}]`

func NewStorage(address aptos.AccountAddress, client aptos.AptosRpcClient) StorageInterface {
	contract := bind.NewBoundContract(address, "platform", "storage", client)
	return StorageContract{
		BoundContract:  contract,
		storageEncoder: storageEncoder{BoundContract: contract},
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

type DispatcherV2 struct {
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

type TestProof struct {
}

type TestProof2 struct {
}

type TestProof3 struct {
}

type TestProof4 struct {
}

type StorageContract struct {
	*bind.BoundContract
	storageEncoder
}

var _ StorageInterface = StorageContract{}

func (c StorageContract) Encoder() StorageEncoder {
	return c.storageEncoder
}

// View Functions

func (c StorageContract) ParseReportMetadata(opts *bind.CallOpts, metadata []byte) (ReportMetadata, error) {
	module, function, typeTags, args, err := c.storageEncoder.ParseReportMetadata(metadata)
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

func (c StorageContract) MigrateToV2(opts *bind.TransactOpts, callbackAddresses []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.storageEncoder.MigrateToV2(callbackAddresses)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type storageEncoder struct {
	*bind.BoundContract
}

func (c storageEncoder) ParseReportMetadata(metadata []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("parse_report_metadata", nil, []string{
		"vector<u8>",
	}, []any{
		metadata,
	})
}

func (c storageEncoder) MigrateToV2(callbackAddresses []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("migrate_to_v2", nil, []string{
		"vector<address>",
	}, []any{
		callbackAddresses,
	})
}

func (c storageEncoder) Insert(receiver aptos.AccountAddress, callbackMetadata []byte, callbackData []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c storageEncoder) StorageExists(objAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("storage_exists", nil, []string{
		"address",
	}, []any{
		objAddress,
	})
}

func (c storageEncoder) StorageAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("storage_address", nil, []string{}, []any{})
}
