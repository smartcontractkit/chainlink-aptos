// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_offramp

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

type OfframpInterface interface {
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (byte, error)
	GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error)
	GetMerkleRoot(opts *bind.CallOpts, root []byte) (uint64, error)
	GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (SourceChainConfig, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)
	LatestConfigDetails(opts *bind.CallOpts, ocrPluginType byte) ([]byte, byte, byte, bool, [][]byte, []aptos.AccountAddress, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSecs uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error)
	ManuallyExecute(opts *bind.TransactOpts, reportBytes []byte) (*api.PendingTransaction, error)
	Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures [][]byte) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSecs uint32) (*api.PendingTransaction, error)
	ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error)
	SetOcr3Config(opts *bind.TransactOpts, configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error)
}

const FunctionInfo = `[{"package":"ccip","module":"offramp","name":"apply_source_chain_config_updates","parameters":[{"name":"source_chains_selector","type":"vector\u003cu64\u003e"},{"name":"source_chains_is_enabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_is_rmn_verification_disabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_on_ramp","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"offramp","name":"commit","parameters":[{"name":"report_context","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"report","type":"vector\u003cu8\u003e"},{"name":"signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"offramp","name":"execute","parameters":[{"name":"report_context","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"report","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"offramp","name":"initialize","parameters":[{"name":"chain_selector","type":"u64"},{"name":"permissionless_execution_threshold_secs","type":"u32"},{"name":"source_chains_selector","type":"vector\u003cu64\u003e"},{"name":"source_chains_is_enabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_is_rmn_verification_disabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_on_ramp","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip","module":"offramp","name":"manually_execute","parameters":[{"name":"report_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip","module":"offramp","name":"set_dynamic_config","parameters":[{"name":"permissionless_execution_threshold_secs","type":"u32"}]},{"package":"ccip","module":"offramp","name":"set_ocr3_config","parameters":[{"name":"config_digest","type":"vector\u003cu8\u003e"},{"name":"ocr_plugin_type","type":"u8"},{"name":"big_f","type":"u8"},{"name":"is_signature_verification_enabled","type":"bool"},{"name":"signers","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"transmitters","type":"vector\u003caddress\u003e"}]}]`

// Structs

type OffRampState struct {
	ChainSelector                        uint64 `move:"u64"`
	PermissionlessExecutionThresholdSecs uint32 `move:"u32"`
	LatestPriceSequenceNumber            uint64 `move:"u64"`
}

type SourceChainConfig struct {
	IsEnabled                 bool   `move:"bool"`
	MinSequenceNumber         uint64 `move:"u64"`
	IsRMNVerificationDisabled bool   `move:"bool"`
	OnRamp                    []byte `move:"vector<u8>"`
}

type RampMessageHeader struct {
	MessageId           []byte `move:"vector<u8>"`
	SourceChainSelector uint64 `move:"u64"`
	DestChainSelector   uint64 `move:"u64"`
	SequenceNumber      uint64 `move:"u64"`
	Nonce               uint64 `move:"u64"`
}

type Any2AptosRampMessage struct {
	Header       RampMessageHeader        `move:"RampMessageHeader"`
	Sender       []byte                   `move:"vector<u8>"`
	Data         []byte                   `move:"vector<u8>"`
	Receiver     aptos.AccountAddress     `move:"address"`
	GasLimit     *big.Int                 `move:"u256"`
	TokenAmounts []Any2AptosTokenTransfer `move:"vector<Any2AptosTokenTransfer>"`
}

type Any2AptosTokenTransfer struct {
	SourcePoolAddress []byte               `move:"vector<u8>"`
	DestTokenAddress  aptos.AccountAddress `move:"address"`
	DestGasAmount     uint32               `move:"u32"`
	ExtraData         []byte               `move:"vector<u8>"`
	Amount            *big.Int             `move:"u256"`
}

type ExecutionReport struct {
	SourceChainSelector uint64               `move:"u64"`
	Message             Any2AptosRampMessage `move:"Any2AptosRampMessage"`
	OffchainTokenData   [][]byte             `move:"vector<vector<u8>>"`
	Proofs              [][]byte             `move:"vector<vector<u8>>"`
}

type CommitReport struct {
	PriceUpdates         PriceUpdates `move:"PriceUpdates"`
	BlessedMerkleRoots   []MerkleRoot `move:"vector<MerkleRoot>"`
	UnblessedMerkleRoots []MerkleRoot `move:"vector<MerkleRoot>"`
	RMNSignatures        [][]byte     `move:"vector<vector<u8>>"`
}

type PriceUpdates struct {
	TokenPriceUpdates []TokenPriceUpdate `move:"vector<TokenPriceUpdate>"`
	GasPriceUpdates   []GasPriceUpdate   `move:"vector<GasPriceUpdate>"`
}

type TokenPriceUpdate struct {
	SourceToken aptos.AccountAddress `move:"address"`
	UsdPerToken *big.Int             `move:"u256"`
}

type GasPriceUpdate struct {
	DestChainSelector uint64   `move:"u64"`
	UsdPerUnitGas     *big.Int `move:"u256"`
}

type MerkleRoot struct {
	SourceChainSelector uint64 `move:"u64"`
	OnRampAddress       []byte `move:"vector<u8>"`
	MinSequenceNumber   uint64 `move:"u64"`
	MaxSequenceNumber   uint64 `move:"u64"`
	MerkleRoot          []byte `move:"vector<u8>"`
}

type StaticConfig struct {
	ChainSelector uint64 `move:"u64"`
}

type DynamicConfig struct {
	PermissionlessExecutionThresholdSecs uint32 `move:"u32"`
}

type StaticConfigSet struct {
	ChainSelector uint64 `move:"u64"`
}

type DynamicConfigSet struct {
	PermissionlessExecutionThresholdSecs uint32 `move:"u32"`
}

type SourceChainConfigSet struct {
	SourceChainSelector       uint64 `move:"u64"`
	IsEnabled                 bool   `move:"bool"`
	MinSequenceNumber         uint64 `move:"u64"`
	IsRMNVerificationDisabled bool   `move:"bool"`
	OnRamp                    []byte `move:"vector<u8>"`
}

type SkippedAlreadyExecuted struct {
	SourceChainSelector uint64 `move:"u64"`
	SequenceNumber      uint64 `move:"u64"`
}

type AlreadyAttempted struct {
	SourceChainSelector uint64 `move:"u64"`
	SequenceNumber      uint64 `move:"u64"`
}

type ExecutionStateChanged struct {
	SourceChainSelector uint64 `move:"u64"`
	SequenceNumber      uint64 `move:"u64"`
	MessageId           []byte `move:"vector<u8>"`
	MessageHash         []byte `move:"vector<u8>"`
	State               byte   `move:"u8"`
}

type CommitReportAccepted struct {
	CommitReport CommitReport `move:"CommitReport"`
}

type SkippedReportExecution struct {
	SourceChainSelector uint64 `move:"u64"`
}

type McmsCallback struct {
}

type Offramp struct {
	OfframpCaller
	OfframpTransactor
}

// View Functions

type OfframpCaller struct {
	*bind.BoundContract
}

func (c OfframpCaller) EncodeTypeAndVersion() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c OfframpCaller) TypeAndVersion(opts *bind.CallOpts) (string, error) {
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

func (c OfframpCaller) EncodeGetExecutionState(sourceChainSelector uint64, sequenceNumber uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_execution_state", nil, []string{
		"u64",
		"u64",
	}, []any{
		sourceChainSelector,
		sequenceNumber,
	})
}

func (c OfframpCaller) GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (byte, error) {
	module, function, typeTags, args, err := c.EncodeGetExecutionState(sourceChainSelector, sequenceNumber)
	if err != nil {
		return *new(byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(byte), err
	}

	var (
		r0 byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(byte), err
	}
	return r0, nil
}

func (c OfframpCaller) EncodeGetLatestPriceSequenceNumber() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_latest_price_sequence_number", nil, []string{}, []any{})
}

func (c OfframpCaller) GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetLatestPriceSequenceNumber()
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

func (c OfframpCaller) EncodeGetMerkleRoot(root []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_merkle_root", nil, []string{
		"vector<u8>",
	}, []any{
		root,
	})
}

func (c OfframpCaller) GetMerkleRoot(opts *bind.CallOpts, root []byte) (uint64, error) {
	module, function, typeTags, args, err := c.EncodeGetMerkleRoot(root)
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

func (c OfframpCaller) EncodeGetSourceChainConfig(sourceChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_source_chain_config", nil, []string{
		"u64",
	}, []any{
		sourceChainSelector,
	})
}

func (c OfframpCaller) GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (SourceChainConfig, error) {
	module, function, typeTags, args, err := c.EncodeGetSourceChainConfig(sourceChainSelector)
	if err != nil {
		return *new(SourceChainConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(SourceChainConfig), err
	}

	var (
		r0 SourceChainConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(SourceChainConfig), err
	}
	return r0, nil
}

func (c OfframpCaller) EncodeGetStaticConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_static_config", nil, []string{}, []any{})
}

func (c OfframpCaller) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := c.EncodeGetStaticConfig()
	if err != nil {
		return *new(StaticConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(StaticConfig), err
	}

	var (
		r0 StaticConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(StaticConfig), err
	}
	return r0, nil
}

func (c OfframpCaller) EncodeGetDynamicConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dynamic_config", nil, []string{}, []any{})
}

func (c OfframpCaller) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := c.EncodeGetDynamicConfig()
	if err != nil {
		return *new(DynamicConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(DynamicConfig), err
	}

	var (
		r0 DynamicConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(DynamicConfig), err
	}
	return r0, nil
}

func (c OfframpCaller) EncodeLatestConfigDetails(ocrPluginType byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("latest_config_details", nil, []string{
		"u8",
	}, []any{
		ocrPluginType,
	})
}

func (c OfframpCaller) LatestConfigDetails(opts *bind.CallOpts, ocrPluginType byte) ([]byte, byte, byte, bool, [][]byte, []aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.EncodeLatestConfigDetails(ocrPluginType)
	if err != nil {
		return *new([]byte), *new(byte), *new(byte), *new(bool), *new([][]byte), *new([]aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), *new(byte), *new(byte), *new(bool), *new([][]byte), *new([]aptos.AccountAddress), err
	}

	var (
		r0 []byte
		r1 byte
		r2 byte
		r3 bool
		r4 [][]byte
		r5 []aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2, &r3, &r4, &r5); err != nil {
		return *new([]byte), *new(byte), *new(byte), *new(bool), *new([][]byte), *new([]aptos.AccountAddress), err
	}
	return r0, r1, r2, r3, r4, r5, nil
}

// Entry Functions

type OfframpTransactor struct {
	*bind.BoundContract
}

func (c OfframpTransactor) EncodeInitialize(chainSelector uint64, permissionlessExecutionThresholdSecs uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
		"u32",
		"vector<u64>",
		"vector<bool>",
		"vector<bool>",
		"vector<vector<u8>>",
	}, []any{
		chainSelector,
		permissionlessExecutionThresholdSecs,
		sourceChainsSelector,
		sourceChainsIsEnabled,
		sourceChainsIsRMNVerificationDisabled,
		sourceChainsOnRamp,
	})
}

func (c OfframpTransactor) Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSecs uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeInitialize(chainSelector, permissionlessExecutionThresholdSecs, sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnRamp)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeExecute(reportContext [][]byte, report []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute", nil, []string{
		"vector<vector<u8>>",
		"vector<u8>",
	}, []any{
		reportContext,
		report,
	})
}

func (c OfframpTransactor) Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeExecute(reportContext, report)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeManuallyExecute(reportBytes []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("manually_execute", nil, []string{
		"vector<u8>",
	}, []any{
		reportBytes,
	})
}

func (c OfframpTransactor) ManuallyExecute(opts *bind.TransactOpts, reportBytes []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeManuallyExecute(reportBytes)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeCommit(reportContext [][]byte, report []byte, signatures [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("commit", nil, []string{
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<vector<u8>>",
	}, []any{
		reportContext,
		report,
		signatures,
	})
}

func (c OfframpTransactor) Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeCommit(reportContext, report, signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeSetDynamicConfig(permissionlessExecutionThresholdSecs uint32) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_dynamic_config", nil, []string{
		"u32",
	}, []any{
		permissionlessExecutionThresholdSecs,
	})
}

func (c OfframpTransactor) SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSecs uint32) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeSetDynamicConfig(permissionlessExecutionThresholdSecs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeApplySourceChainConfigUpdates(sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("apply_source_chain_config_updates", nil, []string{
		"vector<u64>",
		"vector<bool>",
		"vector<bool>",
		"vector<vector<u8>>",
	}, []any{
		sourceChainsSelector,
		sourceChainsIsEnabled,
		sourceChainsIsRMNVerificationDisabled,
		sourceChainsOnRamp,
	})
}

func (c OfframpTransactor) ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeApplySourceChainConfigUpdates(sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnRamp)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpTransactor) EncodeSetOcr3Config(configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_ocr3_config", nil, []string{
		"vector<u8>",
		"u8",
		"u8",
		"bool",
		"vector<vector<u8>>",
		"vector<address>",
	}, []any{
		configDigest,
		ocrPluginType,
		bigF,
		isSignatureVerificationEnabled,
		signers,
		transmitters,
	})
}

func (c OfframpTransactor) SetOcr3Config(opts *bind.TransactOpts, configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.EncodeSetOcr3Config(configDigest, ocrPluginType, bigF, isSignatureVerificationEnabled, signers, transmitters)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}
