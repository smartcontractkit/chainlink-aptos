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
	StageDataAndExecute(opts *bind.TransactOpts, role byte, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error)
	ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSExecutorEncoder
}

type MCMSExecutorEncoder interface {
	StageData(dataChunk []byte, partialProofs [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	StageDataAndExecute(role byte, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ClearStagedData() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms_executor","name":"clear_staged_data","parameters":null},{"package":"mcms","module":"mcms_executor","name":"stage_data","parameters":[{"name":"data_chunk","type":"vector\u003cu8\u003e"},{"name":"partial_proofs","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms_executor","name":"stage_data_and_execute","parameters":[{"name":"role","type":"u8"},{"name":"chain_id","type":"u256"},{"name":"multisig","type":"address"},{"name":"nonce","type":"u64"},{"name":"to","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function","type":"0x1::string::String"},{"name":"data_chunk","type":"vector\u003cu8\u003e"},{"name":"partial_proofs","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

func NewMCMSExecutor(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSExecutorInterface {
	contract := bind.NewBoundContract(address, "mcms", "mcms_executor", client)
	return MCMSExecutorContract{
		BoundContract:       contract,
		mcmsExecutorEncoder: mcmsExecutorEncoder{BoundContract: contract},
	}
}

// Structs

type PendingExecute struct {
	Data   []byte   `move:"vector<u8>"`
	Proofs [][]byte `move:"vector<vector<u8>>"`
}

type MCMSExecutorContract struct {
	*bind.BoundContract
	mcmsExecutorEncoder
}

var _ MCMSExecutorInterface = MCMSExecutorContract{}

func (c MCMSExecutorContract) Encoder() MCMSExecutorEncoder {
	return c.mcmsExecutorEncoder
}

// View Functions

// Entry Functions

func (c MCMSExecutorContract) StageData(opts *bind.TransactOpts, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsExecutorEncoder.StageData(dataChunk, partialProofs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSExecutorContract) StageDataAndExecute(opts *bind.TransactOpts, role byte, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsExecutorEncoder.StageDataAndExecute(role, chainId, multisig, nonce, to, moduleName, function, dataChunk, partialProofs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSExecutorContract) ClearStagedData(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsExecutorEncoder.ClearStagedData()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsExecutorEncoder struct {
	*bind.BoundContract
}

func (c mcmsExecutorEncoder) StageData(dataChunk []byte, partialProofs [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_data", nil, []string{
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		dataChunk,
		partialProofs,
	})
}

func (c mcmsExecutorEncoder) StageDataAndExecute(role byte, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, dataChunk []byte, partialProofs [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("stage_data_and_execute", nil, []string{
		"u8",
		"u256",
		"address",
		"u64",
		"address",
		"0x1::string::String",
		"0x1::string::String",
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		role,
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

func (c mcmsExecutorEncoder) ClearStagedData() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("clear_staged_data", nil, []string{}, []any{})
}
