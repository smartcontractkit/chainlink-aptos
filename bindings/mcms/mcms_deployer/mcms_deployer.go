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
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_deployer","name":"cleanup_staging_area","parameters":null},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk_and_publish_to_object","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"new_owner_seed","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms_deployer","name":"stage_code_chunk_and_upgrade_object_code","parameters":[{"name":"metadata_chunk","type":"vector\u003cu8\u003e"},{"name":"code_indices","type":"vector\u003cu16\u003e"},{"name":"code_chunks","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"code_object_address","type":"address"}]}]`

// Structs

type StagingArea struct {
	MetadataSerialized []byte `move:"vector<u8>"`
	LastModuleIdx      uint64 `move:"u64"`
}

type MCMSDeployer struct {
	MCMSDeployerCaller
	MCMSDeployerTransactor
}

// View Functions

type MCMSDeployerCaller struct {
	*bind.BoundContract
}

// Entry Functions

type MCMSDeployerTransactor struct {
	*bind.BoundContract
}

func (c MCMSDeployerTransactor) EncodeStageCodeChunk(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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

func (c MCMSDeployerTransactor) StageCodeChunk(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeStageCodeChunk(metadataChunk, codeIndices, codeChunks)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerTransactor) EncodeStageCodeChunkAndPublishToObject(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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

func (c MCMSDeployerTransactor) StageCodeChunkAndPublishToObject(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeStageCodeChunkAndPublishToObject(metadataChunk, codeIndices, codeChunks, newOwnerSeed)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerTransactor) EncodeStageCodeChunkAndUpgradeObjectCode(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
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

func (c MCMSDeployerTransactor) StageCodeChunkAndUpgradeObjectCode(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeStageCodeChunkAndUpgradeObjectCode(metadataChunk, codeIndices, codeChunks, codeObjectAddress)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSDeployerTransactor) EncodeCleanupStagingArea() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("cleanup_staging_area", nil, []string{}, []any{})
}

func (c MCMSDeployerTransactor) CleanupStagingArea(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeCleanupStagingArea()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}
