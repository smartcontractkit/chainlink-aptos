// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms

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

type MCMS interface {
	GetConfig(opts *bind.CallOpts) (Config, error)
	GetOpCount(opts *bind.CallOpts) (uint64, error)
	GetRoot(opts *bind.CallOpts) ([]byte, uint64, error)
	GetRootMetadata(opts *bind.CallOpts) (RootMetadata, error)

	SetRoot(opts *bind.TransactOpts, root []byte, validUntil uint64, chainId *big.Int, multisig aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, data []byte, proof [][]byte) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSEncoder
}

type MCMSEncoder interface {
	GetConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOpCount() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRoot() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRootMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetRoot(root []byte, validUntil uint64, chainId *big.Int, multisig aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Execute(chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, data []byte, proof [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetConfig(signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms","name":"execute","parameters":[{"name":"chain_id","type":"u256"},{"name":"multisig","type":"address"},{"name":"nonce","type":"u64"},{"name":"to","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"proof","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms","name":"set_config","parameters":[{"name":"signer_addresses","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"signer_groups","type":"vector\u003cu8\u003e"},{"name":"group_quorums","type":"vector\u003cu8\u003e"},{"name":"group_parents","type":"vector\u003cu8\u003e"},{"name":"clear_root","type":"bool"}]},{"package":"mcms","module":"mcms","name":"set_root","parameters":[{"name":"root","type":"vector\u003cu8\u003e"},{"name":"valid_until","type":"u64"},{"name":"chain_id","type":"u256"},{"name":"multisig","type":"address"},{"name":"pre_op_count","type":"u64"},{"name":"post_op_count","type":"u64"},{"name":"override_previous_root","type":"bool"},{"name":"metadata_proof","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

func NewMCMS(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMS {
	contract := bind.NewBoundContract(address, "mcms", "mcms", client)
	return MCMSContract{
		BoundContract: contract,
		mcmsEncoder:   mcmsEncoder{BoundContract: contract},
	}
}

// Structs

type MultisigState struct {
	Config                 Config                 `move:"Config"`
	ExpiringRootAndOpCount ExpiringRootAndOpCount `move:"ExpiringRootAndOpCount"`
	RootMetadata           RootMetadata           `move:"RootMetadata"`
}

type RootMetadata struct {
	ChainId              *big.Int             `move:"u256"`
	Multisig             aptos.AccountAddress `move:"address"`
	PreOpCount           uint64               `move:"u64"`
	PostOpCount          uint64               `move:"u64"`
	OverridePreviousRoot bool                 `move:"bool"`
}

type Op struct {
	ChainId    *big.Int             `move:"u256"`
	Multisig   aptos.AccountAddress `move:"address"`
	Nonce      uint64               `move:"u64"`
	To         aptos.AccountAddress `move:"address"`
	ModuleName string               `move:"0x1::string::String"`
	Function   string               `move:"0x1::string::String"`
	Data       []byte               `move:"vector<u8>"`
}

type Signer struct {
	Addr  []byte `move:"vector<u8>"`
	Index byte   `move:"u8"`
	Group byte   `move:"u8"`
}

type Config struct {
	Signers      []Signer `move:"vector<Signer>"`
	GroupQuorums []byte   `move:"vector<u8>"`
	GroupParents []byte   `move:"vector<u8>"`
}

type ExpiringRootAndOpCount struct {
	Root       []byte `move:"vector<u8>"`
	ValidUntil uint64 `move:"u64"`
	OpCount    uint64 `move:"u64"`
}

type ConfigSet struct {
	Config        Config `move:"Config"`
	IsRootCleared bool   `move:"bool"`
}

type NewRoot struct {
	Root       []byte       `move:"vector<u8>"`
	ValidUntil uint64       `move:"u64"`
	Metadata   RootMetadata `move:"RootMetadata"`
}

type OpExecuted struct {
	Nonce      uint64               `move:"u64"`
	To         aptos.AccountAddress `move:"address"`
	ModuleName string               `move:"0x1::string::String"`
	Function   string               `move:"0x1::string::String"`
	Data       []byte               `move:"vector<u8>"`
}

type MCMSContract struct {
	*bind.BoundContract
	mcmsEncoder
}

var _ MCMS = MCMSContract{}

func (c MCMSContract) Encoder() MCMSEncoder {
	return c.mcmsEncoder
}

// View Functions

func (c MCMSContract) GetConfig(opts *bind.CallOpts) (Config, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetConfig()
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

func (c MCMSContract) GetOpCount(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetOpCount()
	if err != nil {
		return *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), err
	}

	var (
		r0 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(uint64), err
	}
	return r0, nil
}

func (c MCMSContract) GetRoot(opts *bind.CallOpts) ([]byte, uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetRoot()
	if err != nil {
		return *new([]byte), *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), *new(uint64), err
	}

	var (
		r0 []byte
		r1 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1); err != nil {
		return *new([]byte), *new(uint64), err
	}
	return r0, r1, nil
}

func (c MCMSContract) GetRootMetadata(opts *bind.CallOpts) (RootMetadata, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetRootMetadata()
	if err != nil {
		return *new(RootMetadata), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(RootMetadata), err
	}

	var (
		r0 RootMetadata
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(RootMetadata), err
	}
	return r0, nil
}

// Entry Functions

func (c MCMSContract) SetRoot(opts *bind.TransactOpts, root []byte, validUntil uint64, chainId *big.Int, multisig aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.SetRoot(root, validUntil, chainId, multisig, preOpCount, postOpCount, overridePreviousRoot, metadataProof, signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSContract) Execute(opts *bind.TransactOpts, chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, data []byte, proof [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.Execute(chainId, multisig, nonce, to, moduleName, function, data, proof)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSContract) SetConfig(opts *bind.TransactOpts, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.SetConfig(signerAddresses, signerGroups, groupQuorums, groupParents, clearRoot)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsEncoder struct {
	*bind.BoundContract
}

func (c mcmsEncoder) GetConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_config", nil, []string{}, []any{})
}

func (c mcmsEncoder) GetOpCount() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_op_count", nil, []string{}, []any{})
}

func (c mcmsEncoder) GetRoot() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_root", nil, []string{}, []any{})
}

func (c mcmsEncoder) GetRootMetadata() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_root_metadata", nil, []string{}, []any{})
}

func (c mcmsEncoder) SetRoot(root []byte, validUntil uint64, chainId *big.Int, multisig aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_root", nil, []string{
		"vector<u8>",
		"u64",
		"u256",
		"address",
		"u64",
		"u64",
		"bool",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		root,
		validUntil,
		chainId,
		multisig,
		preOpCount,
		postOpCount,
		overridePreviousRoot,
		metadataProof,
		signatures,
	})
}

func (c mcmsEncoder) Execute(chainId *big.Int, multisig aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, function string, data []byte, proof [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute", nil, []string{
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
		data,
		proof,
	})
}

func (c mcmsEncoder) SetConfig(signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_config", nil, []string{
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<u8>",
		"vector<u8>",
		"bool",
	}, []any{
		signerAddresses,
		signerGroups,
		groupQuorums,
		groupParents,
		clearRoot,
	})
}
