// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms_deployer

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

type MCMSDeployerInterface interface {
	StageCodeChunk(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error)
	StageCodeChunkAndPublishToObject(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (*api.PendingTransaction, error)
	StageCodeChunkAndUpgradeObjectCode(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	CleanupStagingArea(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSDeployerEncoder
}

type MCMSDeployerEncoder interface {
	StageCodeChunk(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StageCodeChunkAndPublishToObject(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StageCodeChunkAndUpgradeObjectCode(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CleanupStagingArea() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CleanupStagingAreaInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_deployer","name":"cleanup_staging_area","parameters":null},{"package":"mcms","module":"mcms_deployer","name":"cleanup_staging_area_internal","parameters":null},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk_and_publish_to_object","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"new_owner_seed","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk_and_upgrade_object_code","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"code_object_address","type":"address"}]}]`

func NewMCMSDeployer(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSDeployerInterface {
	contract := bind.NewBoundContract(address, "mcms", "mcms_deployer", client)
	return MCMSDeployerContract{
		BoundContract:       contract,
		mcmsDeployerEncoder: mcmsDeployerEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_CODE_MISMATCH uint64 = 1
)

// Structs

type StagingArea struct {
	MetadataSerialized []byte `move:"vector<u8>"`
	LastModuleIdx      uint64 `move:"u64"`
}

type MCMSDeployerContract struct {
	*bind.BoundContract
	mcmsDeployerEncoder
}

var _ MCMSDeployerInterface = MCMSDeployerContract{}

func (c MCMSDeployerContract) Encoder() MCMSDeployerEncoder {
	return c.mcmsDeployerEncoder
}

// View Functions

// Entry Functions

func (c MCMSDeployerContract) StageCodeChunk(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsDeployerEncoder.StageCodeChunk(metadataChunk, codeIndices, codeChunks)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerContract) StageCodeChunkAndPublishToObject(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsDeployerEncoder.StageCodeChunkAndPublishToObject(metadataChunk, codeIndices, codeChunks, newOwnerSeed)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerContract) StageCodeChunkAndUpgradeObjectCode(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsDeployerEncoder.StageCodeChunkAndUpgradeObjectCode(metadataChunk, codeIndices, codeChunks, codeObjectAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerContract) CleanupStagingArea(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsDeployerEncoder.CleanupStagingArea()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsDeployerEncoder struct {
	*bind.BoundContract
}

func (c mcmsDeployerEncoder) StageCodeChunk(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_code_chunk", nil, []string{
		"vector<u8>",
		"vector<u16>",
		"vector<vector<u8>>",
	}, []any{
		metadataChunk,
		codeIndices,
		codeChunks,
	})
}

func (c mcmsDeployerEncoder) StageCodeChunkAndPublishToObject(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_code_chunk_and_publish_to_object", nil, []string{
		"vector<u8>",
		"vector<u16>",
		"vector<vector<u8>>",
		"vector<u8>",
	}, []any{
		metadataChunk,
		codeIndices,
		codeChunks,
		newOwnerSeed,
	})
}

func (c mcmsDeployerEncoder) StageCodeChunkAndUpgradeObjectCode(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_code_chunk_and_upgrade_object_code", nil, []string{
		"vector<u8>",
		"vector<u16>",
		"vector<vector<u8>>",
		"address",
	}, []any{
		metadataChunk,
		codeIndices,
		codeChunks,
		codeObjectAddress,
	})
}

func (c mcmsDeployerEncoder) CleanupStagingArea() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("cleanup_staging_area", nil, []string{}, []any{})
}

func (c mcmsDeployerEncoder) CleanupStagingAreaInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("cleanup_staging_area_internal", nil, []string{}, []any{})
}
