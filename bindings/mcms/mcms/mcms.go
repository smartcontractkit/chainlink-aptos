package module_mcms

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"
)

type MCMSInterface interface {
	GetConfig(opts *bind.CallOpts) (Config, error)
	GetOpCount(opts *bind.CallOpts) (opcount uint64, err error)
	GetRoot(opts *bind.CallOpts) (root common.Hash, validUntil uint64, err error)
	GetRootMetadata(opts *bind.CallOpts) (RootMetadata, error)

	SetRoot(opts *bind.TransactOpts, root common.Hash, validUntil uint64, metadata RootMetadata, metadataProof []common.Hash, signatures [][]byte) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, op Op, proof []common.Hash) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, signerAddresses []common.Address, signerGroups []uint8, groupQuorums []uint8, groupParents []uint8, clearRoot bool) (*api.PendingTransaction, error)
}

var _ MCMSInterface = MCMS{}

type MCMS struct {
	MCMSCaller
	MCMSTransactor
}

type RootMetadata struct {
	ChainId              *big.Int
	Multisig             aptos.AccountAddress
	PreOpCount           uint64
	PostOpCount          uint64
	OverridePreviousRoot bool
}

type Op struct {
	ChainId    *big.Int
	Multisig   aptos.AccountAddress
	Nonce      uint64
	To         aptos.AccountAddress
	ModuleName string
	Function   string
	Data       []byte
}

func ArgsToData(args [][]byte) []byte {
	data := []byte{}
	for _, arg := range args {
		data = append(data, arg...)
	}
	return data
}

type Signer struct {
	Addr  common.Address
	Index uint8
	Group uint8
}

type Config struct {
	Signers      []Signer
	GroupQuorums []uint8
	GroupParents []uint8
}

type ConfigSet struct {
	Config        Config
	IsRootCleared bool
}

func (c ConfigSet) EventName() string {
	return "ConfigSet"
}

type NewRoot struct {
	Root       [32]byte
	ValidUntil uint64
	Metadata   RootMetadata
}

func (n NewRoot) EventName() string {
	return "NewRoot"
}

type OpExecuted struct {
	Nonce      uint64
	To         aptos.AccountAddress
	ModuleName string
	Function   string
	Data       []byte
}

func (o OpExecuted) EventName() string {
	return "OpExecuted"
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress
	To   aptos.AccountAddress
}

func (o OwnershipTransferRequested) EventName() string {
	return "OwnershipTransferRequested"
}

type OwnershipTransferred struct {
	From aptos.AccountAddress
	To   aptos.AccountAddress
}

func (o OwnershipTransferred) EventName() string {
	return "OwnershipTransferred"
}

type MCMSCaller struct {
	*bind.BoundContract
}

func (m MCMSCaller) EncodeGetConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("get_config", nil, nil, nil)
}

func (m MCMSCaller) GetConfig(opts *bind.CallOpts) (Config, error) {
	module, function, typeTags, args, err := m.EncodeGetConfig()
	if err != nil {
		return Config{}, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return Config{}, err
	}

	var (
		config Config
	)

	if err := codec.DecodeAptosJsonArray(data, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (m MCMSCaller) EncodeGetOpCount() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("get_op_count", nil, nil, nil)
}

func (m MCMSCaller) GetOpCount(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := m.EncodeGetOpCount()
	if err != nil {
		return 0, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var (
		opcount uint64
	)

	if err := codec.DecodeAptosJsonArray(data, &opcount); err != nil {
		return 0, err
	}
	return opcount, nil
}

func (m MCMSCaller) EncodeGetRoot() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("get_root", nil, nil, nil)
}

func (m MCMSCaller) GetRoot(opts *bind.CallOpts) (common.Hash, uint64, error) {
	module, function, typeTags, args, err := m.EncodeGetRoot()
	if err != nil {
		return common.Hash{}, 0, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return common.Hash{}, 0, err
	}

	var (
		root       common.Hash
		validUntil uint64
	)

	if err := codec.DecodeAptosJsonArray(data, &root, &validUntil); err != nil {
		return common.Hash{}, 0, err
	}

	return root, validUntil, nil
}

func (m MCMSCaller) EncodeGetRootMetadata() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("get_root_metadata", nil, nil, nil)
}

func (m MCMSCaller) GetRootMetadata(opts *bind.CallOpts) (RootMetadata, error) {
	module, function, typeTags, args, err := m.EncodeGetRootMetadata()
	if err != nil {
		return RootMetadata{}, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return RootMetadata{}, err
	}

	var (
		metadata RootMetadata
	)

	if err := codec.DecodeAptosJsonArray(data, &metadata); err != nil {
		return RootMetadata{}, err
	}

	return metadata, nil
}

type MCMSTransactor struct {
	*bind.BoundContract
}

func (m MCMSTransactor) EncodeSetRoot(
	root common.Hash,
	validUntil uint64,
	metadata RootMetadata,
	metadataProof []common.Hash,
	signatures [][]byte,
) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"set_root",
		nil,
		[]string{
			"vector<u8>",
			"u64",
			"u256",
			"address",
			"u64",
			"u64",
			"bool",
			"vector<vector<u8>>",
			"vector<vector<u8>>",
		},
		[]any{
			root,
			validUntil,
			metadata.ChainId,
			metadata.Multisig,
			metadata.PreOpCount,
			metadata.PostOpCount,
			metadata.OverridePreviousRoot,
			metadataProof,
			signatures,
		})
}

func (m MCMSTransactor) SetRoot(
	opts *bind.TransactOpts,
	root common.Hash,
	validUntil uint64,
	metadata RootMetadata,
	metadataProof []common.Hash,
	signatures [][]byte,
) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeSetRoot(root, validUntil, metadata, metadataProof, signatures)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSTransactor) EncodeExecute(
	op Op,
	proof []common.Hash,
) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"execute",
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
			proof,
		})
}

func (m MCMSTransactor) Execute(
	opts *bind.TransactOpts,
	op Op,
	proof []common.Hash,
) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeExecute(op, proof)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSTransactor) EncodeSetConfig(
	signerAddresses []common.Address,
	signerGroups []uint8,
	groupQuorums []uint8,
	groupParents []uint8,
	clearRoot bool,
) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"set_config",
		nil,
		[]string{
			"vector<vector<u8>>",
			"vector<u8>",
			"vector<u8>",
			"vector<u8>",
			"bool",
		},
		[]any{
			signerAddresses,
			signerGroups,
			groupQuorums,
			groupParents,
			clearRoot,
		})
}

func (m MCMSTransactor) SetConfig(
	opts *bind.TransactOpts,
	signerAddresses []common.Address,
	signerGroups []uint8,
	groupQuorums []uint8,
	groupParents []uint8,
	clearRoot bool,
) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeSetConfig(signerAddresses, signerGroups, groupQuorums, groupParents, clearRoot)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}
