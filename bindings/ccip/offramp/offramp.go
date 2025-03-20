package module_offramp

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/ethereum/go-ethereum/common"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

type OfframpInterface interface {
	GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (uint8, error)
	GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error)
	GetMerkleRoot(opts *bind.CallOpts, sourceChainSelector uint64, root common.Hash) (uint64, error)
	GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (bool, uint64, error)
	GetInboundNonce(opts *bind.CallOpts, sourceChainSelector uint64, sender common.Address) (uint64, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)
	LatestConfigDetails(opts *bind.CallOpts, ocrPluginType uint8) (common.Hash, uint8, uint8, bool, []common.Address, []aptos.AccountAddress, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnramp [][]byte) (*api.PendingTransaction, error)
	ManuallyExecute(opts *bind.TransactOpts, reportsBytes []byte) (*api.PendingTransaction, error)
	Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures []common.Hash) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error)
	ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainSelectors []uint64, sourceChainIsEnabled []bool) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool) (*api.PendingTransaction, error)
	SetOCR3Config(opts *bind.TransactOpts, configDigest common.Hash, ocrPluginType uint8, bigF uint8, isSignatureVerificationEnabled bool, signers []common.Address, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

type StaticConfig struct {
	ChainSelector uint64
}

type DynamicConfig struct {
	PermissionlessExecutionThresholdSecs uint32
	IsRMNVerificationDisabled            bool
}

var _ OfframpInterface = Offramp{}

type Offramp struct {
	OfframpCaller
	OfframpTransactor
}

type OfframpCaller struct {
	*bind.BoundContract
}

func (o OfframpCaller) EncodeGetExecutionState(sourceChainSelector uint64, sequenceNumber uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_execution_state", nil, []string{"u64", "u64"}, []any{sourceChainSelector, sequenceNumber})
}

func (o OfframpCaller) GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (uint8, error) {
	module, function, typeTags, args, err := o.EncodeGetExecutionState(sourceChainSelector, sequenceNumber)
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var state uint8
	if err := codec.DecodeAptosJsonArray(data, &state); err != nil {
		return 0, err
	}
	return state, nil
}

func (o OfframpCaller) EncodeGetLatestPriceSequenceNumber() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_latest_price_sequence_number", nil, nil, nil)
}

func (o OfframpCaller) GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetLatestPriceSequenceNumber()
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var sequence uint64
	if err := codec.DecodeAptosJsonArray(data, &sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

func (o OfframpCaller) EncodeGetMerkleRoot(sourceChainSelector uint64, root common.Hash) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_merkle_root", nil, []string{"u64", "vector<u8>"}, []any{sourceChainSelector, root[:]})
}

func (o OfframpCaller) GetMerkleRoot(opts *bind.CallOpts, sourceChainSelector uint64, root common.Hash) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetMerkleRoot(sourceChainSelector, root)
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var sequence uint64
	if err := codec.DecodeAptosJsonArray(data, &sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

func (o OfframpCaller) EncodeGetSourceChainConfig(sourceChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_source_chain_config", nil, []string{"u64"}, []any{sourceChainSelector})
}

func (o OfframpCaller) GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (bool, uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetSourceChainConfig(sourceChainSelector)
	if err != nil {
		return false, 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, 0, err
	}

	var isEnabled bool
	var latestNonce uint64
	if err := codec.DecodeAptosJsonArray(data, &isEnabled, &latestNonce); err != nil {
		return false, 0, err
	}
	return isEnabled, latestNonce, nil
}

func (o OfframpCaller) EncodeGetInboundNonce(sourceChainSelector uint64, sender common.Address) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_inbound_nonce", nil, []string{"u64", "address"}, []any{sourceChainSelector, sender})
}

func (o OfframpCaller) GetInboundNonce(opts *bind.CallOpts, sourceChainSelector uint64, sender common.Address) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetInboundNonce(sourceChainSelector, sender)
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var nonce uint64
	if err := codec.DecodeAptosJsonArray(data, &nonce); err != nil {
		return 0, err
	}
	return nonce, nil
}

func (o OfframpCaller) EncodeGetStaticConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_static_config", nil, nil, nil)
}

func (o OfframpCaller) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := o.EncodeGetStaticConfig()
	if err != nil {
		return StaticConfig{}, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return StaticConfig{}, err
	}

	var config StaticConfig
	if err := codec.DecodeAptosJsonArray(data, &config); err != nil {
		return StaticConfig{}, err
	}
	return config, nil
}

func (o OfframpCaller) EncodeGetDynamicConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_dynamic_config", nil, nil, nil)
}

func (o OfframpCaller) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := o.EncodeGetDynamicConfig()
	if err != nil {
		return DynamicConfig{}, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return DynamicConfig{}, err
	}

	var config DynamicConfig
	if err := codec.DecodeAptosJsonArray(data, &config); err != nil {
		return DynamicConfig{}, err
	}
	return config, nil
}

func (o OfframpCaller) EncodeLatestConfigDetails(ocrPluginType uint8) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("latest_config_details", nil, []string{"u8"}, []any{ocrPluginType})
}

func (o OfframpCaller) LatestConfigDetails(opts *bind.CallOpts, ocrPluginType uint8) (common.Hash, uint8, uint8, bool, []common.Address, []aptos.AccountAddress, error) {
	module, function, typeTags, args, err := o.EncodeLatestConfigDetails(ocrPluginType)
	if err != nil {
		return common.Hash{}, 0, 0, false, nil, nil, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return common.Hash{}, 0, 0, false, nil, nil, err
	}

	var configDigest []byte
	var bigF uint8
	var n uint8
	var isSignatureVerificationEnabled bool
	var signers []common.Address
	var transmitters []aptos.AccountAddress

	if err := codec.DecodeAptosJsonArray(data, &configDigest, &bigF, &n, &isSignatureVerificationEnabled, &signers, &transmitters); err != nil {
		return common.Hash{}, 0, 0, false, nil, nil, err
	}
	return common.BytesToHash(configDigest), bigF, n, isSignatureVerificationEnabled, signers, transmitters, nil
}

type OfframpTransactor struct {
	*bind.BoundContract
}

func (o OfframpTransactor) EncodeInitialize(chainSelector uint64, permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnramp [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("initialize", nil, []string{"u64", "u32", "bool", "vector<u64>", "vector<bool>", "vector<bool>", "vector<vector<u8>>"}, []any{chainSelector, permissionlessExecutionThresholdSecs, isRmnVerificationDisabled, sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnramp})
}

func (o OfframpTransactor) Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnramp [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeInitialize(chainSelector, permissionlessExecutionThresholdSecs, isRmnVerificationDisabled, sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnramp)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeManuallyExecute(reportsBytes []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("manually_execute", nil, []string{"vector<u8>"}, []any{reportsBytes})
}

func (o OfframpTransactor) ManuallyExecute(opts *bind.TransactOpts, reportsBytes []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeManuallyExecute(reportsBytes)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeCommit(reportContext [][]byte, report []byte, signatures []common.Hash) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("commit", nil, []string{"vector<vector<u8>>", "vector<u8>", "vector<vector<u8>>"}, []any{reportContext, report, signatures})
}

func (o OfframpTransactor) Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures []common.Hash) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeCommit(reportContext, report, signatures)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeExecute(reportContext [][]byte, report []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("execute", nil, []string{"vector<vector<u8>>", "vector<u8>"}, []any{reportContext, report})
}

func (o OfframpTransactor) Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeExecute(reportContext, report)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeApplySourceChainConfigUpdates(sourceChainSelectors []uint64, sourceChainIsEnabled []bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("apply_source_chain_config_updates", nil, []string{"vector<u64>", "vector<bool>"}, []any{sourceChainSelectors, sourceChainIsEnabled})
}

func (o OfframpTransactor) ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainSelectors []uint64, sourceChainIsEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeApplySourceChainConfigUpdates(sourceChainSelectors, sourceChainIsEnabled)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeSetDynamicConfig(permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("set_dynamic_config", nil, []string{"u32", "bool"}, []any{permissionlessExecutionThresholdSecs, isRmnVerificationDisabled})
}

func (o OfframpTransactor) SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSecs uint32, isRmnVerificationDisabled bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeSetDynamicConfig(permissionlessExecutionThresholdSecs, isRmnVerificationDisabled)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeSetOCR3Config(configDigest common.Hash, ocrPluginType uint8, bigF uint8, isSignatureVerificationEnabled bool, signers []common.Address, transmitters []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("set_ocr3_config", nil, []string{"vector<u8>", "u8", "u8", "bool", "vector<address>", "vector<address>"}, []any{configDigest[:], ocrPluginType, bigF, isSignatureVerificationEnabled, signers, transmitters})
}

func (o OfframpTransactor) SetOCR3Config(opts *bind.TransactOpts, configDigest common.Hash, ocrPluginType uint8, bigF uint8, isSignatureVerificationEnabled bool, signers []common.Address, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeSetOCR3Config(configDigest, ocrPluginType, bigF, isSignatureVerificationEnabled, signers, transmitters)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeTransferOwnership(to aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("transfer_ownership", nil, []string{"address"}, []any{to})
}

func (o OfframpTransactor) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeTransferOwnership(to)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OfframpTransactor) EncodeAcceptOwnership() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("accept_ownership", nil, nil, nil)
}

func (o OfframpTransactor) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeAcceptOwnership()
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}
