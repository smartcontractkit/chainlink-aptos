package module_rmn_remote

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

// RMNRemoteInterface defines the interface for interacting with the RMNRemote contract
type RMNRemoteInterface interface {
	Verify(opts *bind.CallOpts, merkleRootSourceChainSelectors []uint64, merkleRootMinSequenceNumbers []uint64, merkleRootMaxSequenceNumbers []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error)
	GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error)
	GetLocalChainSelector(opts *bind.CallOpts) (uint64, error)
	GetReportDigestHeader(opts *bind.CallOpts) (common.Hash, error)

	Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error)
	Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
	Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error)
	UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error)
}

// Signer represents a signer in the RMN config
type Signer struct {
	OnchainPublicKey []byte
	NodeIndex        uint64
}

// Config represents the RMN configuration struct
type Config struct {
	RMNHomeContractConfigDigest []byte
	Signers                     []Signer
	FSign                       uint64
}

var _ RMNRemoteInterface = RMNRemote{}

type RMNRemote struct {
	RMNRemoteCaller
	RMNRemoteTransactor
}

type RMNRemoteCaller struct {
	*bind.BoundContract
}

func (r RMNRemoteCaller) EncodeVerify(merkleRootSourceChainSelectors []uint64, merkleRootMinSequenceNumbers []uint64, merkleRootMaxSequenceNumbers []uint64, merkleRootValues [][]byte, signatures [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("verify", nil, []string{
		"vector<u64>",
		"vector<u64>",
		"vector<u64>",
		"vector<vector<u8>>",
		"vector<vector<u8>>",
	}, []any{
		merkleRootSourceChainSelectors,
		merkleRootMinSequenceNumbers,
		merkleRootMaxSequenceNumbers,
		merkleRootValues,
		signatures,
	})
}

func (r RMNRemoteCaller) Verify(opts *bind.CallOpts, merkleRootSourceChainSelectors []uint64, merkleRootMinSequenceNumbers []uint64, merkleRootMaxSequenceNumbers []uint64, merkleRootValues [][]byte, signatures [][]byte) (bool, error) {
	module, function, typeTags, args, err := r.EncodeVerify(merkleRootSourceChainSelectors, merkleRootMinSequenceNumbers, merkleRootMaxSequenceNumbers, merkleRootValues, signatures)
	if err != nil {
		return false, err
	}

	data, err := r.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, err
	}

	var result bool
	if err := codec.DecodeAptosJsonArray(data, &result); err != nil {
		return false, err
	}
	return result, nil
}

func (r RMNRemoteCaller) EncodeGetVersionedConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("get_versioned_config", nil, nil, nil)
}

func (r RMNRemoteCaller) GetVersionedConfig(opts *bind.CallOpts) (uint32, Config, error) {
	module, function, typeTags, args, err := r.EncodeGetVersionedConfig()
	if err != nil {
		return 0, Config{}, err
	}

	data, err := r.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, Config{}, err
	}

	var version uint32
	var config Config
	if err := codec.DecodeAptosJsonArray(data, &version, &config); err != nil {
		return 0, Config{}, err
	}
	return version, config, nil
}

func (r RMNRemoteCaller) EncodeGetLocalChainSelector() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("get_local_chain_selector", nil, nil, nil)
}

func (r RMNRemoteCaller) GetLocalChainSelector(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := r.EncodeGetLocalChainSelector()
	if err != nil {
		return 0, err
	}

	data, err := r.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var selector uint64
	if err := codec.DecodeAptosJsonArray(data, &selector); err != nil {
		return 0, err
	}
	return selector, nil
}

func (r RMNRemoteCaller) EncodeGetReportDigestHeader() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("get_report_digest_header", nil, nil, nil)
}

func (r RMNRemoteCaller) GetReportDigestHeader(opts *bind.CallOpts) (common.Hash, error) {
	module, function, typeTags, args, err := r.EncodeGetReportDigestHeader()
	if err != nil {
		return common.Hash{}, err
	}

	data, err := r.Call(opts, module, function, typeTags, args)
	if err != nil {
		return common.Hash{}, err
	}

	var header common.Hash
	if err := codec.DecodeAptosJsonArray(data, &header); err != nil {
		return common.Hash{}, err
	}
	return header, nil
}

type RMNRemoteTransactor struct {
	*bind.BoundContract
}

func (r RMNRemoteTransactor) EncodeInitialize(localChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("initialize", nil, []string{"u64"}, []any{localChainSelector})
}

func (r RMNRemoteTransactor) Initialize(opts *bind.TransactOpts, localChainSelector uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeInitialize(localChainSelector)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}

func (r RMNRemoteTransactor) EncodeSetConfig(rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("set_config", nil, []string{
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

func (r RMNRemoteTransactor) SetConfig(opts *bind.TransactOpts, rmnHomeContractConfigDigest []byte, signerOnchainPublicKeys [][]byte, nodeIndexes []uint64, fSign uint64) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeSetConfig(rmnHomeContractConfigDigest, signerOnchainPublicKeys, nodeIndexes, fSign)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}

func (r RMNRemoteTransactor) EncodeCurse(subject []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("curse", nil, []string{"vector<u8>"}, []any{subject})
}

func (r RMNRemoteTransactor) Curse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeCurse(subject)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}

func (r RMNRemoteTransactor) EncodeCurseMultiple(subjects [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("curse_multiple", nil, []string{"vector<vector<u8>>"}, []any{subjects})
}

func (r RMNRemoteTransactor) CurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeCurseMultiple(subjects)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}

func (r RMNRemoteTransactor) EncodeUncurse(subject []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("uncurse", nil, []string{"vector<u8>"}, []any{subject})
}

func (r RMNRemoteTransactor) Uncurse(opts *bind.TransactOpts, subject []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeUncurse(subject)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}

func (r RMNRemoteTransactor) EncodeUncurseMultiple(subjects [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("uncurse_multiple", nil, []string{"vector<vector<u8>>"}, []any{subjects})
}

func (r RMNRemoteTransactor) UncurseMultiple(opts *bind.TransactOpts, subjects [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeUncurseMultiple(subjects)
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}
