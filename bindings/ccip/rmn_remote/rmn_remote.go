// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_rmn_remote

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

type RMNRemoteInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	Verify(opts *bind.CallOpts, merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error)
	GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error)
	GetLocalChainSelector(opts *bind.CallOpts) (uint64, error)
	GetReportDigestHeader(opts *bind.CallOpts) ([]byte, error)

	Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error)
	Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
	Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"ccip","module":"rmn_remote","name":"curse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"curse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"get_cursed_subjects","parameters":null},{"package":"ccip","module":"rmn_remote","name":"initialize","parameters":[{"name":"local_chain_selector","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"is_cursed","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"is_cursed_global","parameters":null},{"package":"ccip","module":"rmn_remote","name":"is_cursed_u128","parameters":[{"name":"subject_value","type":"u128"}]},{"package":"ccip","module":"rmn_remote","name":"set_config","parameters":[{"name":"rmn_home_contract_config_digest","type":"vector\u003cu8\u003e"},{"name":"signer_onchain_public_keys","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"node_indexes","type":"vector\u003cu64\u003e"},{"name":"f_sign","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

// Structs

type RMNRemoteState struct {
	LocalChainSelector uint64 `move:"u64"`
	Config             Config `move:"Config"`
	ConfigCount        uint32 `move:"u32"`
}

type Config struct {
	RMNHomeContractConfigDigest []byte   `move:"vector<u8>"`
	Signers                     []Signer `move:"vector<Signer>"`
	FSign                       uint64   `move:"u64"`
}

type Signer struct {
	OnchainPublicKey []byte `move:"vector<u8>"`
	NodeIndex        uint64 `move:"u64"`
}

type Report struct {
	DestChainId                 uint64               `move:"u64"`
	DestChainSelector           uint64               `move:"u64"`
	RMNRemoteContractAddress    aptos.AccountAddress `move:"address"`
	OffRampAddress              aptos.AccountAddress `move:"address"`
	RMNHomeContractConfigDigest []byte               `move:"vector<u8>"`
	MerkleRoots                 []MerkleRoot         `move:"vector<MerkleRoot>"`
}

type MerkleRoot struct {
	SourceChainSelector uint64 `move:"u64"`
	MinSeqNr            uint64 `move:"u64"`
	MaxSeqNr            uint64 `move:"u64"`
	MerkleRoot          []byte `move:"vector<u8>"`
}

type ConfigSet struct {
	Version uint32 `move:"u32"`
	Config  Config `move:"Config"`
}

type Cursed struct {
	Subjects [][]byte `move:"vector<vector<u8>>"`
}

type Uncursed struct {
	Subjects [][]byte `move:"vector<vector<u8>>"`
}

type McmsCallback struct {
}

type RMNRemote struct {
	RMNRemoteCaller
	RMNRemoteTransactor
}

// View Functions

type RMNRemoteCaller struct {
	*bind.BoundContract
}

func (c RMNRemoteCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.EncodeTypeAndVersion()
	if err != nil {
		return *new(string), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(string), err
	}

	var (
		r0 string
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(string), err
	}
	return r0, nil
}

func (c RMNRemoteCaller) EncodeVerify(merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("verify", nil, []string{
		"vector<u64>",
		"vector<u64>",
		"vector<u64>",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		merkleRootSourceChainSelectors,
		merkleRootMinSeqNrs,
		merkleRootMaxSeqNrs,
		merkleRootValues,
		signatures,
	})
}

func (c RMNRemoteCaller) Verify(opts *bind.CallOpts, merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error) {
	module, function, typeTags, args, err := c.EncodeVerify(merkleRootSourceChainSelectors, merkleRootMinSeqNrs, merkleRootMaxSeqNrs, merkleRootValues, signatures)
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

func (c RMNRemoteCaller) EncodeGetVersionedConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_versioned_config", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error) {
	module, function, typeTags, args, err := c.EncodeGetVersionedConfig()
	if err != nil {
		return *new(uint32), *new(Config), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint32), *new(Config), err
	}

	var (
		r0 uint32
		r1 Config
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1); err != nil {
		return *new(uint32), *new(Config), err
	}
	return r0, r1, nil
}

func (c RMNRemoteCaller) EncodeGetLocalChainSelector() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_local_chain_selector", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) GetLocalChainSelector(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetLocalChainSelector()
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

func (c RMNRemoteCaller) EncodeGetReportDigestHeader() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_report_digest_header", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) GetReportDigestHeader(opts *bind.CallOpts) ([]byte, error) {
	module, function, typeTags, args, err := c.EncodeGetReportDigestHeader()
	if err != nil {
		return *new([]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), err
	}

	var (
		r0 []byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]byte), err
	}
	return r0, nil
}

// Entry Functions

type RMNRemoteTransactor struct {
	*bind.BoundContract
}

func (c RMNRemoteTransactor) EncodeInitialize(localChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
	}, []any{
		localChainSelector,
	})
}

func (c RMNRemoteTransactor) Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeInitialize(localChainSelector)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteTransactor) EncodeSetConfig(rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_config", nil, []string{
		"vector<u8>",
		"vector<vector<u8>>",
		"vector<u64>",
		"u64",
	}, []any{
		rmnHomeContractConfigDigest,
		signerOnchainPublicKeys,
		nodeIndexes,
		fSign,
	})
}

func (c RMNRemoteTransactor) SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeSetConfig(rmnHomeContractConfigDigest, signerOnchainPublicKeys, nodeIndexes, fSign)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteTransactor) EncodeCurse(subject []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("curse", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c RMNRemoteTransactor) Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeCurse(subject)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteTransactor) EncodeCurseMultiple(subjects [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("curse_multiple", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		subjects,
	})
}

func (c RMNRemoteTransactor) CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeCurseMultiple(subjects)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteTransactor) EncodeUncurse(subject []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("uncurse", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c RMNRemoteTransactor) Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeUncurse(subject)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteTransactor) EncodeUncurseMultiple(subjects [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("uncurse_multiple", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		subjects,
	})
}

func (c RMNRemoteTransactor) UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeUncurseMultiple(subjects)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Other Functions

func (c RMNRemoteCaller) EncodeGetCursedSubjects() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_cursed_subjects", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) EncodeIsCursedGlobal() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed_global", nil, []string{}, []any{})
}

func (c RMNRemoteCaller) EncodeIsCursed(subject []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c RMNRemoteCaller) EncodeIsCursedU128(subjectValue *big.Int) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed_u128", nil, []string{
		"u128",
	}, []any{
		subjectValue,
	})
}
