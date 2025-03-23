// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms_executor

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

type MCMSExecutorInterface interface {
	StageData(opts *bind.TransactOpts, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error)
	StageDataAndExecute(opts *bind.TransactOpts, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error)
	ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_executor","name":"clear_staged_data","parameters":null},{"package":"mcms","module":"mcms_executor","name":"stage_data","parameters":[{"name":"data_chunk","type":"vector\u003cu8\u003e"},{"name":"partial_proofs","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms_executor","name":"stage_data_and_execute","parameters":[{"name":"chain_id","type":"u256"},{"name":"multisig","type":"address"},{"name":"nonce","type":"u64"},{"name":"to","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function","type":"0x1::string::String"},{"name":"data_chunk","type":"vector\u003cu8\u003e"},{"name":"partial_proofs","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

// Structs

type PendingExecute struct {
	Data   []byte   `move:"vector<u8>"`
	Proofs [][]byte `move:"vector<vector<u8>>"`
}

type MCMSExecutor struct {
	MCMSExecutorCaller
	MCMSExecutorTransactor
}

// View Functions

type MCMSExecutorCaller struct {
	*bind.BoundContract
}

// Entry Functions

type MCMSExecutorTransactor struct {
	*bind.BoundContract
}

func (c MCMSExecutorTransactor) EncodeStageData(dataChunk []byte, partialProofs [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_data", nil, []string{
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		dataChunk,
		partialProofs,
	})
}

func (c MCMSExecutorTransactor) StageData(opts *bind.TransactOpts, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeStageData(dataChunk, partialProofs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSExecutorTransactor) EncodeStageDataAndExecute(chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_data_and_execute", nil, []string{
		"u256",
		"address",
		"u64",
		"address",
		"0x1::string::String",
		"0x1::string::String",
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		chainId,
		multisig,
		nonce,
		to,
		moduleName,
		function,
		dataChunk,
		partialProofs,
	})
}

func (c MCMSExecutorTransactor) StageDataAndExecute(opts *bind.TransactOpts, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeStageDataAndExecute(chainId, multisig, nonce, to, moduleName, function, dataChunk, partialProofs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSExecutorTransactor) EncodeClearStagedData() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("clear_staged_data", nil, []string{}, []any{})
}

func (c MCMSExecutorTransactor) ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeClearStagedData()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}
