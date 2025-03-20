package module_mcms_deployer

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
)

type MCMSDeployerInterface interface {
	StageCodeChunk(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error)
	StageCodeChunkAndPublishToObject(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed string) (*api.PendingTransaction, error)
	StageCodeChunkAndUpgradeObjectCode(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	CleanupStagingArea(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

var _ MCMSDeployerInterface = MCMSDeployer{}

type MCMSDeployer struct {
	MCMSDeployerTransactor
}

type MCMSDeployerTransactor struct {
	*bind.BoundContract
}

func (m MCMSDeployerTransactor) EncodeStageCodeChunk(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"stage_code_chunk",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
		})
}

func (m MCMSDeployerTransactor) StageCodeChunk(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeStageCodeChunk(metadataChunk, codeIndices, codeChunks)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSDeployerTransactor) EncodeStageCodeChunkAndPublishToObject(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed string) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"stage_code_chunk_and_publish_to_object",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
			"vector<u8>",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
			newOwnerSeed,
		},
	)
}

func (m MCMSDeployerTransactor) StageCodeChunkAndPublishToObject(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed string) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeStageCodeChunkAndPublishToObject(metadataChunk, codeIndices, codeChunks, newOwnerSeed)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSDeployerTransactor) EncodeStageCodeChunkAndUpgradeObjectCode(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"stage_code_chunk_and_upgrade_object_code",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
			"address",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
			codeObjectAddress,
		},
	)
}

func (m MCMSDeployerTransactor) StageCodeChunkAndUpgradeObjectCode(opts *bind.TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeStageCodeChunkAndUpgradeObjectCode(metadataChunk, codeIndices, codeChunks, codeObjectAddress)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSDeployerTransactor) EncodeCleanupStagingArea() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("cleanup_staging_area", nil, nil, nil)
}

func (m MCMSDeployerTransactor) CleanupStagingArea(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeCleanupStagingArea()
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}
