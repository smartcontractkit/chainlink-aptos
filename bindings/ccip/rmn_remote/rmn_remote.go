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
	GetArm(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetVersionedConfig(opts *bind.CallOpts) (VersionedConfig, error)
	GetLocalChainSelector(opts *bind.CallOpts) (uint64, error)
	GetReportDigestHeader(opts *bind.CallOpts) ([]byte, error)
	GetCursedSubjects(opts *bind.CallOpts) ([][]byte, error)
	IsCursedGlobal(opts *bind.CallOpts) (bool, error)
	IsCursed(opts *bind.CallOpts, subject []byte) (bool, error)
	IsCursedU128(opts *bind.CallOpts, subjectValue *big.Int) (bool, error)

	Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error)
	Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
	Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RMNRemoteEncoder
}

type RMNRemoteEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Verify(merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetArm() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetVersionedConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetLocalChainSelector() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetReportDigestHeader() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetCursedSubjects() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursedGlobal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursed(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursedU128(subjectValue *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(localChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetConfig(rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Curse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Uncurse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UncurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"rmn_remote","name":"curse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"curse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"initialize","parameters":[{"name":"local_chain_selector","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"rmn_remote","name":"set_config","parameters":[{"name":"rmn_home_contract_config_digest","type":"vector\u003cu8\u003e"},{"name":"signer_onchain_public_keys","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"node_indexes","type":"vector\u003cu64\u003e"},{"name":"f_sign","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

func NewRMNRemote(address aptos.AccountAddress, client aptos.AptosRpcClient) RMNRemoteInterface {
	contract := bind.NewBoundContract(address, "ccip", "rmn_remote", client)
	return RMNRemoteContract{
		BoundContract:    contract,
		rmnRemoteEncoder: rmnRemoteEncoder{BoundContract: contract},
	}
}

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

type VersionedConfig struct {
	Version uint32 `move:"u32"`
	Config  Config `move:"Config"`
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

type RMNRemoteContract struct {
	*bind.BoundContract
	rmnRemoteEncoder
}

var _ RMNRemoteInterface = RMNRemoteContract{}

func (c RMNRemoteContract) Encoder() RMNRemoteEncoder {
	return c.rmnRemoteEncoder
}

// View Functions

func (c RMNRemoteContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.TypeAndVersion()
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

func (c RMNRemoteContract) Verify(opts *bind.CallOpts, merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.Verify(merkleRootSourceChainSelectors, merkleRootMinSeqNrs, merkleRootMaxSeqNrs, merkleRootValues, signatures)
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

func (c RMNRemoteContract) GetArm(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetArm()
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

func (c RMNRemoteContract) GetVersionedConfig(opts *bind.CallOpts) (VersionedConfig, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetVersionedConfig()
	if err != nil {
		return *new(VersionedConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(VersionedConfig), err
	}

	var (
		r0 VersionedConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(VersionedConfig), err
	}
	return r0, nil
}

func (c RMNRemoteContract) GetLocalChainSelector(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetLocalChainSelector()
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

func (c RMNRemoteContract) GetReportDigestHeader(opts *bind.CallOpts) ([]byte, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetReportDigestHeader()
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

func (c RMNRemoteContract) GetCursedSubjects(opts *bind.CallOpts) ([][]byte, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetCursedSubjects()
	if err != nil {
		return *new([][]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([][]byte), err
	}

	var (
		r0 [][]byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([][]byte), err
	}
	return r0, nil
}

func (c RMNRemoteContract) IsCursedGlobal(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.IsCursedGlobal()
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

func (c RMNRemoteContract) IsCursed(opts *bind.CallOpts, subject []byte) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.IsCursed(subject)
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

func (c RMNRemoteContract) IsCursedU128(opts *bind.CallOpts, subjectValue *big.Int) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.IsCursedU128(subjectValue)
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

// Entry Functions

func (c RMNRemoteContract) Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.Initialize(localChainSelector)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.SetConfig(rmnHomeContractConfigDigest, signerOnchainPublicKeys, nodeIndexes, fSign)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.Curse(subject)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.CurseMultiple(subjects)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.Uncurse(subject)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.UncurseMultiple(subjects)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type rmnRemoteEncoder struct {
	*bind.BoundContract
}

func (c rmnRemoteEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) Verify(merkleRootSourceChainSelectors []uint64, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c rmnRemoteEncoder) GetArm() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_arm", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) GetVersionedConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_versioned_config", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) GetLocalChainSelector() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_local_chain_selector", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) GetReportDigestHeader() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_report_digest_header", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) GetCursedSubjects() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_cursed_subjects", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) IsCursedGlobal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed_global", nil, []string{}, []any{})
}

func (c rmnRemoteEncoder) IsCursed(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c rmnRemoteEncoder) IsCursedU128(subjectValue *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_cursed_u128", nil, []string{
		"u128",
	}, []any{
		subjectValue,
	})
}

func (c rmnRemoteEncoder) Initialize(localChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
	}, []any{
		localChainSelector,
	})
}

func (c rmnRemoteEncoder) SetConfig(rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c rmnRemoteEncoder) Curse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("curse", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c rmnRemoteEncoder) CurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("curse_multiple", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		subjects,
	})
}

func (c rmnRemoteEncoder) Uncurse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("uncurse", nil, []string{
		"vector<u8>",
	}, []any{
		subject,
	})
}

func (c rmnRemoteEncoder) UncurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("uncurse_multiple", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		subjects,
	})
}

func (c rmnRemoteEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
