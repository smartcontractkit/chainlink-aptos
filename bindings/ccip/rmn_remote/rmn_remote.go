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
	Verify(opts *bind.CallOpts, offRampAddress aptos.AccountAddress, merkleRootSourceChainSelectors []uint64, merkleRootOnRampAddresses [][]byte, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error)
	GetArm(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error)
	GetLocalChainSelector(opts *bind.CallOpts) (uint64, error)
	GetReportDigestHeader(opts *bind.CallOpts) ([]byte, error)
	GetCursedSubjects(opts *bind.CallOpts) ([][]byte, error)
	IsCursedGlobal(opts *bind.CallOpts) (bool, error)
	IsCursed(opts *bind.CallOpts, subject []byte) (bool, error)
	IsCursedU128(opts *bind.CallOpts, subjectValue *big.Int) (bool, error)
	IsAllowedCurser(opts *bind.CallOpts, curser aptos.AccountAddress) (bool, error)
	GetAllowedCursers(opts *bind.CallOpts) ([]aptos.AccountAddress, error)

	Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error)
	Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
	Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
	InitializeAllowedCursersV2(opts *bind.TransactOpts, initialCursers []aptos.AccountAddress) (*api.PendingTransaction, error)
	AddAllowedCursers(opts *bind.TransactOpts, cursersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error)
	RemoveAllowedCursers(opts *bind.TransactOpts, cursersToRemove []aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RMNRemoteEncoder
}

type RMNRemoteEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Verify(offRampAddress aptos.AccountAddress, merkleRootSourceChainSelectors []uint64, merkleRootOnRampAddresses [][]byte, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetArm() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetVersionedConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetLocalChainSelector() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetReportDigestHeader() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetCursedSubjects() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursedGlobal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursed(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsCursedU128(subjectValue *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsAllowedCurser(curser aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllowedCursers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(localChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetConfig(rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Curse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Uncurse(subject []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	UncurseMultiple(subjects [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	InitializeAllowedCursersV2(initialCursers []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AddAllowedCursers(cursersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RemoveAllowedCursers(cursersToRemove []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AssertOwnerOrAllowedCurser(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip","module":"rmn_remote","name":"add_allowed_cursers","parameters":[{"name":"cursers_to_add","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"assert_owner_or_allowed_curser","parameters":[{"name":"caller","type":"address"}]},{"package":"ccip","module":"rmn_remote","name":"curse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"curse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"initialize","parameters":[{"name":"local_chain_selector","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"initialize_allowed_cursers_v2","parameters":[{"name":"initial_cursers","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip","module":"rmn_remote","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip","module":"rmn_remote","name":"remove_allowed_cursers","parameters":[{"name":"cursers_to_remove","type":"vector\u003caddress\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"set_config","parameters":[{"name":"rmn_home_contract_config_digest","type":"vector\u003cu8\u003e"},{"name":"signer_onchain_public_keys","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"node_indexes","type":"vector\u003cu64\u003e"},{"name":"f_sign","type":"u64"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse","parameters":[{"name":"subject","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"rmn_remote","name":"uncurse_multiple","parameters":[{"name":"subjects","type":"vector\u003cvector\u003cu8\u003e\u003e"}]}]`

func NewRMNRemote(address aptos.AccountAddress, client aptos.AptosRpcClient) RMNRemoteInterface {
	contract := bind.NewBoundContract(address, "ccip", "rmn_remote", client)
	return RMNRemoteContract{
		BoundContract:    contract,
		rmnRemoteEncoder: rmnRemoteEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_ALREADY_INITIALIZED                    uint64 = 1
	E_ALREADY_CURSED                         uint64 = 2
	E_CONFIG_NOT_SET                         uint64 = 3
	E_DUPLICATE_SIGNER                       uint64 = 4
	E_INVALID_SIGNATURE                      uint64 = 5
	E_INVALID_SIGNER_ORDER                   uint64 = 6
	E_NOT_ENOUGH_SIGNERS                     uint64 = 7
	E_NOT_CURSED                             uint64 = 8
	E_OUT_OF_ORDER_SIGNATURES                uint64 = 9
	E_THRESHOLD_NOT_MET                      uint64 = 10
	E_UNEXPECTED_SIGNER                      uint64 = 11
	E_ZERO_VALUE_NOT_ALLOWED                 uint64 = 12
	E_MERKLE_ROOT_LENGTH_MISMATCH            uint64 = 13
	E_INVALID_DIGEST_LENGTH                  uint64 = 14
	E_SIGNERS_MISMATCH                       uint64 = 15
	E_INVALID_SUBJECT_LENGTH                 uint64 = 16
	E_INVALID_PUBLIC_KEY_LENGTH              uint64 = 17
	E_UNKNOWN_FUNCTION                       uint64 = 18
	E_NOT_OWNER_OR_ALLOWED_CURSER            uint64 = 19
	E_ALLOWED_CURSERS_V2_ALREADY_INITIALIZED uint64 = 20
	E_ALLOWED_CURSERS_V2_NOT_INITIALIZED     uint64 = 21
	E_CURSER_ALREADY_ALLOWED                 uint64 = 22
	E_CURSER_NOT_ALLOWED                     uint64 = 23
)

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
	OnRampAddress       []byte `move:"vector<u8>"`
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

type AllowedCursersV2 struct {
}

type AllowedCursersAdded struct {
	Cursers []aptos.AccountAddress `move:"vector<address>"`
}

type AllowedCursersRemoved struct {
	Cursers []aptos.AccountAddress `move:"vector<address>"`
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

func (c RMNRemoteContract) Verify(opts *bind.CallOpts, offRampAddress aptos.AccountAddress, merkleRootSourceChainSelectors []uint64, merkleRootOnRampAddresses [][]byte, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.Verify(offRampAddress, merkleRootSourceChainSelectors, merkleRootOnRampAddresses, merkleRootMinSeqNrs, merkleRootMaxSeqNrs, merkleRootValues, signatures)
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

func (c RMNRemoteContract) GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetVersionedConfig()
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

func (c RMNRemoteContract) IsAllowedCurser(opts *bind.CallOpts, curser aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.IsAllowedCurser(curser)
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

func (c RMNRemoteContract) GetAllowedCursers(opts *bind.CallOpts) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.GetAllowedCursers()
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]aptos.AccountAddress), err
	}

	var (
		r0 []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]aptos.AccountAddress), err
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

func (c RMNRemoteContract) InitializeAllowedCursersV2(opts *bind.TransactOpts, initialCursers []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.InitializeAllowedCursersV2(initialCursers)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) AddAllowedCursers(opts *bind.TransactOpts, cursersToAdd []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.AddAllowedCursers(cursersToAdd)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RMNRemoteContract) RemoveAllowedCursers(opts *bind.TransactOpts, cursersToRemove []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.rmnRemoteEncoder.RemoveAllowedCursers(cursersToRemove)
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

func (c rmnRemoteEncoder) Verify(offRampAddress aptos.AccountAddress, merkleRootSourceChainSelectors []uint64, merkleRootOnRampAddresses [][]byte, merkleRootMinSeqNrs []uint64, merkleRootMaxSeqNrs []uint64, merkleRootValues [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("verify", nil, []string{
		"address",
		"vector<u64>",
		"vector<vector<u8>>",
		"vector<u64>",
		"vector<u64>",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		offRampAddress,
		merkleRootSourceChainSelectors,
		merkleRootOnRampAddresses,
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

func (c rmnRemoteEncoder) IsAllowedCurser(curser aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_allowed_curser", nil, []string{
		"address",
	}, []any{
		curser,
	})
}

func (c rmnRemoteEncoder) GetAllowedCursers() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_allowed_cursers", nil, []string{}, []any{})
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

func (c rmnRemoteEncoder) InitializeAllowedCursersV2(initialCursers []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize_allowed_cursers_v2", nil, []string{
		"vector<address>",
	}, []any{
		initialCursers,
	})
}

func (c rmnRemoteEncoder) AddAllowedCursers(cursersToAdd []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("add_allowed_cursers", nil, []string{
		"vector<address>",
	}, []any{
		cursersToAdd,
	})
}

func (c rmnRemoteEncoder) RemoveAllowedCursers(cursersToRemove []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("remove_allowed_cursers", nil, []string{
		"vector<address>",
	}, []any{
		cursersToRemove,
	})
}

func (c rmnRemoteEncoder) AssertOwnerOrAllowedCurser(caller aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("assert_owner_or_allowed_curser", nil, []string{
		"address",
	}, []any{
		caller,
	})
}

func (c rmnRemoteEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c rmnRemoteEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}
