// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_registry

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

type RegistryInterface interface {
	GetMigrationStatus(opts *bind.CallOpts) (bool, error)
	GetWorkflowConfig(opts *bind.CallOpts) (WorkflowConfig, error)
	GetFeeds(opts *bind.CallOpts) ([]FeedConfig, error)
	GetFeedMetadata(opts *bind.CallOpts, feedIds [][]byte) ([]FeedMetadata, error)
	GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error)

	RegisterCallbacks(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	SetFeeds(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string, configId []byte) (*api.PendingTransaction, error)
	RemoveFeeds(opts *bind.TransactOpts, feedIds [][]byte) (*api.PendingTransaction, error)
	UpdateDescriptions(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string) (*api.PendingTransaction, error)
	SetWorkflowConfig(opts *bind.TransactOpts, allowedWorkflowOwners [][]byte, allowedWorkflowNames [][]byte) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RegistryEncoder
}

type RegistryEncoder interface {
	GetMigrationStatus() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetWorkflowConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFeeds() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFeedMetadata(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterCallbacks() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetFeeds(feedIds [][]byte, descriptions []string, configId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RemoveFeeds(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UpdateDescriptions(feedIds [][]byte, descriptions []string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetWorkflowConfig(allowedWorkflowOwners [][]byte, allowedWorkflowNames [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetFeedsUnchecked(feedIds [][]byte, descriptions []string, configId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ToU32be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ToU256be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	NewProof() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	NewProofSecondary() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	OnReport(Meta aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	OnReportSecondary(Meta aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetBenchmarks(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetBenchmarksUnchecked(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetReports(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetReportsUnchecked(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"data_feeds","module":"registry","name":"accept_ownership","parameters":null},{"package":"data_feeds","module":"registry","name":"get_benchmarks","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"get_benchmarks_unchecked","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"get_reports","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"get_reports_unchecked","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"get_state_addr","parameters":null},{"package":"data_feeds","module":"registry","name":"new_proof","parameters":null},{"package":"data_feeds","module":"registry","name":"new_proof_secondary","parameters":null},{"package":"data_feeds","module":"registry","name":"on_report","parameters":[{"name":"_meta","type":"address"}]},{"package":"data_feeds","module":"registry","name":"on_report_secondary","parameters":[{"name":"_meta","type":"address"}]},{"package":"data_feeds","module":"registry","name":"register_callbacks","parameters":null},{"package":"data_feeds","module":"registry","name":"remove_feeds","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"set_feeds","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"descriptions","type":"vector\u003c0x1::string::String\u003e"},{"name":"config_id","type":"vector\u003cu8\u003e"}]},{"package":"data_feeds","module":"registry","name":"set_feeds_unchecked","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"descriptions","type":"vector\u003c0x1::string::String\u003e"},{"name":"config_id","type":"vector\u003cu8\u003e"}]},{"package":"data_feeds","module":"registry","name":"set_workflow_config","parameters":[{"name":"allowed_workflow_owners","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"allowed_workflow_names","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"data_feeds","module":"registry","name":"to_u256be","parameters":[{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"data_feeds","module":"registry","name":"to_u32be","parameters":[{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"data_feeds","module":"registry","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]},{"package":"data_feeds","module":"registry","name":"update_descriptions","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"descriptions","type":"vector\u003c0x1::string::String\u003e"}]}]`

func NewRegistry(address aptos.AccountAddress, client aptos.AptosRpcClient) RegistryInterface {
	contract := bind.NewBoundContract(address, "data_feeds", "registry", client)
	return RegistryContract{
		BoundContract:   contract,
		registryEncoder: registryEncoder{BoundContract: contract},
	}
}

// Constants
const (
	ENOT_OWNER                   uint64 = 1
	EDUPLICATE_ELEMENTS          uint64 = 2
	EFEED_EXISTS                 uint64 = 3
	EFEED_NOT_CONFIGURED         uint64 = 4
	ECONFIG_NOT_CONFIGURED       uint64 = 5
	EUNEQUAL_ARRAY_LENGTHS       uint64 = 6
	EINVALID_REPORT              uint64 = 7
	EUNAUTHORIZED_WORKFLOW_NAME  uint64 = 8
	EUNAUTHORIZED_WORKFLOW_OWNER uint64 = 9
	ECANNOT_TRANSFER_TO_SELF     uint64 = 10
	ENOT_PROPOSED_OWNER          uint64 = 11
	EEMPTY_WORKFLOW_OWNERS       uint64 = 12
	EINVALID_RAW_REPORT          uint64 = 13
	EALREADY_MIGRATED            uint64 = 14
	SCHEMA_V3                    uint16 = 3
	SCHEMA_V4                    uint16 = 4
)

// Structs

type Registry struct {
	OwnerAddress          aptos.AccountAddress             `move:"address"`
	PendingOwnerAddress   aptos.AccountAddress             `move:"address"`
	Feeds                 *bind.StdSimpleMap[[]byte, Feed] `move:"std::simple_map::SimpleMap<vector<u8>,Feed>"`
	AllowedWorkflowOwners [][]byte                         `move:"vector<vector<u8>>"`
	AllowedWorkflowNames  [][]byte                         `move:"vector<vector<u8>>"`
}

type RegistryMigrationStatus struct {
	CallbackRegistered bool `move:"bool"`
}

type Feed struct {
	Description          string   `move:"0x1::string::String"`
	ConfigId             []byte   `move:"vector<u8>"`
	Benchmark            *big.Int `move:"u256"`
	Report               []byte   `move:"vector<u8>"`
	ObservationTimestamp *big.Int `move:"u256"`
}

type Benchmark struct {
	Benchmark            *big.Int `move:"u256"`
	ObservationTimestamp *big.Int `move:"u256"`
}

type Report struct {
	Report               []byte   `move:"vector<u8>"`
	ObservationTimestamp *big.Int `move:"u256"`
}

type FeedMetadata struct {
	Description string `move:"0x1::string::String"`
	ConfigId    []byte `move:"vector<u8>"`
}

type WorkflowConfig struct {
	AllowedWorkflowOwners [][]byte `move:"vector<vector<u8>>"`
	AllowedWorkflowNames  [][]byte `move:"vector<vector<u8>>"`
}

type FeedConfig struct {
	FeedId []byte `move:"vector<u8>"`
	Feed   Feed   `move:"Feed"`
}

type FeedDescriptionUpdated struct {
	FeedId      []byte `move:"vector<u8>"`
	Description string `move:"0x1::string::String"`
}

type FeedRemoved struct {
	FeedId []byte `move:"vector<u8>"`
}

type FeedSet struct {
	FeedId      []byte `move:"vector<u8>"`
	Description string `move:"0x1::string::String"`
	ConfigId    []byte `move:"vector<u8>"`
}

type FeedUnset struct {
	FeedId []byte `move:"vector<u8>"`
}

type FeedUpdated struct {
	FeedId    []byte   `move:"vector<u8>"`
	Timestamp *big.Int `move:"u256"`
	Benchmark *big.Int `move:"u256"`
	Report    []byte   `move:"vector<u8>"`
}

type StaleReport struct {
	FeedId          []byte   `move:"vector<u8>"`
	LatestTimestamp *big.Int `move:"u256"`
	ReportTimestamp *big.Int `move:"u256"`
}

type WriteSkippedFeedNotSet struct {
	FeedId []byte `move:"vector<u8>"`
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferred struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OnReceive struct {
}

type OnReceiveSecondary struct {
}

type RegistryContract struct {
	*bind.BoundContract
	registryEncoder
}

var _ RegistryInterface = RegistryContract{}

func (c RegistryContract) Encoder() RegistryEncoder {
	return c.registryEncoder
}

// View Functions

func (c RegistryContract) GetMigrationStatus(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.registryEncoder.GetMigrationStatus()
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

func (c RegistryContract) GetWorkflowConfig(opts *bind.CallOpts) (WorkflowConfig, error) {
	module, function, typeTags, args, err := c.registryEncoder.GetWorkflowConfig()
	if err != nil {
		return *new(WorkflowConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(WorkflowConfig), err
	}

	var (
		r0 WorkflowConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(WorkflowConfig), err
	}
	return r0, nil
}

func (c RegistryContract) GetFeeds(opts *bind.CallOpts) ([]FeedConfig, error) {
	module, function, typeTags, args, err := c.registryEncoder.GetFeeds()
	if err != nil {
		return *new([]FeedConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]FeedConfig), err
	}

	var (
		r0 []FeedConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]FeedConfig), err
	}
	return r0, nil
}

func (c RegistryContract) GetFeedMetadata(opts *bind.CallOpts, feedIds [][]byte) ([]FeedMetadata, error) {
	module, function, typeTags, args, err := c.registryEncoder.GetFeedMetadata(feedIds)
	if err != nil {
		return *new([]FeedMetadata), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]FeedMetadata), err
	}

	var (
		r0 []FeedMetadata
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]FeedMetadata), err
	}
	return r0, nil
}

func (c RegistryContract) GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.registryEncoder.GetOwner()
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

func (c RegistryContract) RegisterCallbacks(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.RegisterCallbacks()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) SetFeeds(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string, configId []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.SetFeeds(feedIds, descriptions, configId)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) RemoveFeeds(opts *bind.TransactOpts, feedIds [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.RemoveFeeds(feedIds)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) UpdateDescriptions(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.UpdateDescriptions(feedIds, descriptions)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) SetWorkflowConfig(opts *bind.TransactOpts, allowedWorkflowOwners [][]byte, allowedWorkflowNames [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.SetWorkflowConfig(allowedWorkflowOwners, allowedWorkflowNames)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RegistryContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.registryEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type registryEncoder struct {
	*bind.BoundContract
}

func (c registryEncoder) GetMigrationStatus() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_migration_status", nil, []string{}, []any{})
}

func (c registryEncoder) GetWorkflowConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_workflow_config", nil, []string{}, []any{})
}

func (c registryEncoder) GetFeeds() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_feeds", nil, []string{}, []any{})
}

func (c registryEncoder) GetFeedMetadata(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_feed_metadata", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c registryEncoder) GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_owner", nil, []string{}, []any{})
}

func (c registryEncoder) RegisterCallbacks() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_callbacks", nil, []string{}, []any{})
}

func (c registryEncoder) SetFeeds(feedIds [][]byte, descriptions []string, configId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_feeds", nil, []string{
		"vector<vector<u8>>",
		"vector<0x1::string::String>",
		"vector<u8>",
	}, []any{
		feedIds,
		descriptions,
		configId,
	})
}

func (c registryEncoder) RemoveFeeds(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("remove_feeds", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c registryEncoder) UpdateDescriptions(feedIds [][]byte, descriptions []string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("update_descriptions", nil, []string{
		"vector<vector<u8>>",
		"vector<0x1::string::String>",
	}, []any{
		feedIds,
		descriptions,
	})
}

func (c registryEncoder) SetWorkflowConfig(allowedWorkflowOwners [][]byte, allowedWorkflowNames [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_workflow_config", nil, []string{
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		allowedWorkflowOwners,
		allowedWorkflowNames,
	})
}

func (c registryEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c registryEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c registryEncoder) GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_addr", nil, []string{}, []any{})
}

func (c registryEncoder) SetFeedsUnchecked(feedIds [][]byte, descriptions []string, configId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_feeds_unchecked", nil, []string{
		"vector<vector<u8>>",
		"vector<0x1::string::String>",
		"vector<u8>",
	}, []any{
		feedIds,
		descriptions,
		configId,
	})
}

func (c registryEncoder) ToU32be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("to_u32be", nil, []string{
		"vector<u8>",
	}, []any{
		data,
	})
}

func (c registryEncoder) ToU256be(data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("to_u256be", nil, []string{
		"vector<u8>",
	}, []any{
		data,
	})
}

func (c registryEncoder) NewProof() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new_proof", nil, []string{}, []any{})
}

func (c registryEncoder) NewProofSecondary() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new_proof_secondary", nil, []string{}, []any{})
}

func (c registryEncoder) OnReport(Meta aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("on_report", nil, []string{
		"address",
	}, []any{
		Meta,
	})
}

func (c registryEncoder) OnReportSecondary(Meta aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("on_report_secondary", nil, []string{
		"address",
	}, []any{
		Meta,
	})
}

func (c registryEncoder) GetBenchmarks(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_benchmarks", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c registryEncoder) GetBenchmarksUnchecked(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_benchmarks_unchecked", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c registryEncoder) GetReports(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_reports", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c registryEncoder) GetReportsUnchecked(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_reports_unchecked", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}
