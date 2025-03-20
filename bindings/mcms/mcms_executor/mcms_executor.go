package module_mcms_executor

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
)

type MCMSExecutorInterface interface {
	StageData(opts *bind.TransactOpts, dataChunk []byte, partialProofs []common.Hash) (*api.PendingTransaction, error)
	StageDataAndExecute(opts *bind.TransactOpts, op module_mcms.Op, partialProofs []common.Hash) (*api.PendingTransaction, error)
	ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

var _ MCMSExecutorInterface = MCMSExecutor{}

type MCMSExecutor struct {
	MCMSExecutorCaller
	MCMSExecutorTransactor
}

type MCMSExecutorCaller struct {
	*bind.BoundContract
}

type MCMSExecutorTransactor struct {
	*bind.BoundContract
}

func (m MCMSExecutorTransactor) EncodeStageData(dataChunk []byte, partialProofs []common.Hash) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"stage_data",
		nil,
		[]string{
			"vector<u8>",
			"vector<vector<u8>>",
		},
		[]any{
			dataChunk,
			partialProofs,
		})
}

func (m MCMSExecutorTransactor) StageData(opts *bind.TransactOpts, dataChunk []byte, partialProofs []common.Hash) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeStageData(dataChunk, partialProofs)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSExecutorTransactor) EncodeStageDataAndExecute(op module_mcms.Op, partialProofs []common.Hash) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"stage_data_and_execute",
		nil,
		[]string{
			"u256",
			"address",
			"u64",
			"address",
			"0x1::string::String",
			"0x1::string::String",
			"vector<u8>",
			"vector<vector<u8>>",
		},
		[]any{
			op.ChainId,
			op.Multisig,
			op.Nonce,
			op.To,
			op.ModuleName,
			op.Function,
			op.Data,
			partialProofs,
		})
}

func (m MCMSExecutorTransactor) StageDataAndExecute(opts *bind.TransactOpts, op module_mcms.Op, partialProofs []common.Hash) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeStageDataAndExecute(op, partialProofs)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSExecutorTransactor) EncodeClearStagedData() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("clear_staged_data", nil, nil, nil)
}

func (m MCMSExecutorTransactor) ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeClearStagedData()
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}
