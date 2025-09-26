// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_offramp

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_ocr3_base "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/ocr3_base"
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
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (byte, error)
	GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error)
	GetMerkleRoot(opts *bind.CallOpts, root []byte) (uint64, error)
	GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (SourceChainConfig, error)
	GetAllSourceChainConfigs(opts *bind.CallOpts) ([]uint64, []SourceChainConfig, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)
	CalculateMetadataHash(opts *bind.CallOpts, sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) ([]byte, error)
	CalculateMessageHash(opts *bind.CallOpts, messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender []byte, receiver aptos.AccountAddress, onRamp []byte, data []byte, gasLimit *big.Int, sourcePoolAddresses [][]byte, destTokenAddresses []aptos.AccountAddress, destGasAmounts []uint32, extraDatas [][]byte, amounts []*big.Int) ([]byte, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)
	LatestConfigDetails(opts *bind.CallOpts, ocrPluginType byte) (module_ocr3_base.OCRConfig, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSeconds uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error)
	ManuallyExecute(opts *bind.TransactOpts, reportBytes []byte) (*api.PendingTransaction, error)
	Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures [][]byte) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSeconds uint32) (*api.PendingTransaction, error)
	ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	SetOcr3Config(opts *bind.TransactOpts, configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() OfframpEncoder
}

type OfframpEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetExecutionState(sourceChainSelector uint64, sequenceNumber uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetLatestPriceSequenceNumber() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetMerkleRoot(root []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetSourceChainConfig(sourceChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetAllSourceChainConfigs() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDynamicConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMetadataHash(sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMessageHash(messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender []byte, receiver aptos.AccountAddress, onRamp []byte, data []byte, gasLimit *big.Int, sourcePoolAddresses [][]byte, destTokenAddresses []aptos.AccountAddress, destGasAmounts []uint32, extraDatas [][]byte, amounts []*big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	LatestConfigDetails(ocrPluginType byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(chainSelector uint64, permissionlessExecutionThresholdSeconds uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Execute(reportContext [][]byte, report []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ManuallyExecute(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Commit(reportContext [][]byte, report []byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetDynamicConfig(permissionlessExecutionThresholdSeconds uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ApplySourceChainConfigUpdates(sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetOcr3Config(configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateMetadataHashInlined(sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DeserializeCommitReport(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DeserializeExecutionReport(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CreateStaticConfig(chainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CreateDynamicConfig(permissionlessExecutionThresholdSeconds uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_offramp","module":"offramp","name":"accept_ownership","parameters":null},{"package":"ccip_offramp","module":"offramp","name":"apply_source_chain_config_updates","parameters":[{"name":"source_chains_selector","type":"vector\u003cu64\u003e"},{"name":"source_chains_is_enabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_is_rmn_verification_disabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_on_ramp","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"calculate_metadata_hash_inlined","parameters":[{"name":"source_chain_selector","type":"u64"},{"name":"dest_chain_selector","type":"u64"},{"name":"on_ramp","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"commit","parameters":[{"name":"report_context","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"report","type":"vector\u003cu8\u003e"},{"name":"signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"create_dynamic_config","parameters":[{"name":"permissionless_execution_threshold_seconds","type":"u32"}]},{"package":"ccip_offramp","module":"offramp","name":"create_static_config","parameters":[{"name":"chain_selector","type":"u64"}]},{"package":"ccip_offramp","module":"offramp","name":"deserialize_commit_report","parameters":[{"name":"report_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"deserialize_execution_report","parameters":[{"name":"report_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"execute","parameters":[{"name":"report_context","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"report","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip_offramp","module":"offramp","name":"get_state_address_internal","parameters":null},{"package":"ccip_offramp","module":"offramp","name":"initialize","parameters":[{"name":"chain_selector","type":"u64"},{"name":"permissionless_execution_threshold_seconds","type":"u32"},{"name":"source_chains_selector","type":"vector\u003cu64\u003e"},{"name":"source_chains_is_enabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_is_rmn_verification_disabled","type":"vector\u003cbool\u003e"},{"name":"source_chains_on_ramp","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"manually_execute","parameters":[{"name":"report_bytes","type":"vector\u003cu8\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip_offramp","module":"offramp","name":"register_mcms_entrypoint","parameters":null},{"package":"ccip_offramp","module":"offramp","name":"set_dynamic_config","parameters":[{"name":"permissionless_execution_threshold_seconds","type":"u32"}]},{"package":"ccip_offramp","module":"offramp","name":"set_ocr3_config","parameters":[{"name":"config_digest","type":"vector\u003cu8\u003e"},{"name":"ocr_plugin_type","type":"u8"},{"name":"big_f","type":"u8"},{"name":"is_signature_verification_enabled","type":"bool"},{"name":"signers","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"transmitters","type":"vector\u003caddress\u003e"}]},{"package":"ccip_offramp","module":"offramp","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewOfframp(address aptos.AccountAddress, client aptos.AptosRpcClient) OfframpInterface {
	contract := bind.NewBoundContract(address, "ccip_offramp", "offramp", client)
	return OfframpContract{
		BoundContract:  contract,
		offrampEncoder: offrampEncoder{BoundContract: contract},
	}
}

// Constants
const (
	EXECUTION_STATE_UNTOUCHED                                byte   = 0
	EXECUTION_STATE_SUCCESS                                  byte   = 2
	E_ALREADY_INITIALIZED                                    uint64 = 1
	E_SOURCE_CHAIN_SELECTORS_MISMATCH                        uint64 = 2
	E_ZERO_CHAIN_SELECTOR                                    uint64 = 3
	E_UNKNOWN_SOURCE_CHAIN_SELECTOR                          uint64 = 4
	E_MUST_BE_OUT_OF_ORDER_EXEC                              uint64 = 5
	E_SOURCE_CHAIN_SELECTOR_MISMATCH                         uint64 = 6
	E_DEST_CHAIN_SELECTOR_MISMATCH                           uint64 = 7
	E_TOKEN_DATA_MISMATCH                                    uint64 = 8
	E_ROOT_NOT_COMMITTED                                     uint64 = 9
	E_MANUAL_EXECUTION_NOT_YET_ENABLED                       uint64 = 10
	E_SOURCE_CHAIN_NOT_ENABLED                               uint64 = 11
	E_COMMIT_ON_RAMP_MISMATCH                                uint64 = 12
	E_INVALID_INTERVAL                                       uint64 = 13
	E_INVALID_ROOT                                           uint64 = 14
	E_ROOT_ALREADY_COMMITTED                                 uint64 = 15
	E_STALE_COMMIT_REPORT                                    uint64 = 16
	E_UNSUPPORTED_TOKEN                                      uint64 = 17
	E_UNKNOWN_FUNCTION                                       uint64 = 18
	E_CURSED_BY_RMN                                          uint64 = 19
	E_FUNGIBLE_ASSET_TYPE_MISMATCH                           uint64 = 20
	E_FUNGIBLE_ASSET_AMOUNT_MISMATCH                         uint64 = 21
	E_SIGNATURE_VERIFICATION_REQUIRED_IN_COMMIT_PLUGIN       uint64 = 22
	E_SIGNATURE_VERIFICATION_NOT_ALLOWED_IN_EXECUTION_PLUGIN uint64 = 23
	E_RMN_BLESSING_MISMATCH                                  uint64 = 24
	E_INVALID_ON_RAMP_UPDATE                                 uint64 = 25
	E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS               uint64 = 26
)

// Structs

type OffRampDeployment struct {
}

type OffRampState struct {
	ChainSelector                           uint64 `move:"u64"`
	PermissionlessExecutionThresholdSeconds uint32 `move:"u32"`
	LatestPriceSequenceNumber               uint64 `move:"u64"`
}

type SourceChainConfig struct {
	Router                    aptos.AccountAddress `move:"address"`
	IsEnabled                 bool                 `move:"bool"`
	MinSeqNr                  uint64               `move:"u64"`
	IsRMNVerificationDisabled bool                 `move:"bool"`
	OnRamp                    []byte               `move:"vector<u8>"`
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
	MinSeqNr            uint64 `move:"u64"`
	MaxSeqNr            uint64 `move:"u64"`
	MerkleRoot          []byte `move:"vector<u8>"`
}

type StaticConfig struct {
	ChainSelector      uint64               `move:"u64"`
	RMNRemote          aptos.AccountAddress `move:"address"`
	TokenAdminRegistry aptos.AccountAddress `move:"address"`
	NonceManager       aptos.AccountAddress `move:"address"`
}

type DynamicConfig struct {
	FeeQuoter                               aptos.AccountAddress `move:"address"`
	PermissionlessExecutionThresholdSeconds uint32               `move:"u32"`
}

type StaticConfigSet struct {
	StaticConfig StaticConfig `move:"StaticConfig"`
}

type DynamicConfigSet struct {
	DynamicConfig DynamicConfig `move:"DynamicConfig"`
}

type SourceChainConfigSet struct {
	SourceChainSelector uint64            `move:"u64"`
	SourceChainConfig   SourceChainConfig `move:"SourceChainConfig"`
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
	BlessedMerkleRoots   []MerkleRoot `move:"vector<MerkleRoot>"`
	UnblessedMerkleRoots []MerkleRoot `move:"vector<MerkleRoot>"`
	PriceUpdates         PriceUpdates `move:"PriceUpdates"`
}

type SkippedReportExecution struct {
	SourceChainSelector uint64 `move:"u64"`
}

type McmsCallback struct {
}

type OfframpContract struct {
	*bind.BoundContract
	offrampEncoder
}

var _ OfframpInterface = OfframpContract{}

func (c OfframpContract) Encoder() OfframpEncoder {
	return c.offrampEncoder
}

// View Functions

func (c OfframpContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.offrampEncoder.TypeAndVersion()
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

func (c OfframpContract) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetStateAddress()
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

func (c OfframpContract) GetExecutionState(opts *bind.CallOpts, sourceChainSelector uint64, sequenceNumber uint64) (byte, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetExecutionState(sourceChainSelector, sequenceNumber)
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

func (c OfframpContract) GetLatestPriceSequenceNumber(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetLatestPriceSequenceNumber()
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

func (c OfframpContract) GetMerkleRoot(opts *bind.CallOpts, root []byte) (uint64, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetMerkleRoot(root)
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

func (c OfframpContract) GetSourceChainConfig(opts *bind.CallOpts, sourceChainSelector uint64) (SourceChainConfig, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetSourceChainConfig(sourceChainSelector)
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

func (c OfframpContract) GetAllSourceChainConfigs(opts *bind.CallOpts) ([]uint64, []SourceChainConfig, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetAllSourceChainConfigs()
	if err != nil {
		return *new([]uint64), *new([]SourceChainConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]uint64), *new([]SourceChainConfig), err
	}

	var (
		r0 []uint64
		r1 []SourceChainConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1); err != nil {
		return *new([]uint64), *new([]SourceChainConfig), err
	}
	return r0, r1, nil
}

func (c OfframpContract) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetStaticConfig()
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

func (c OfframpContract) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := c.offrampEncoder.GetDynamicConfig()
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

func (c OfframpContract) CalculateMetadataHash(opts *bind.CallOpts, sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) ([]byte, error) {
	module, function, typeTags, args, err := c.offrampEncoder.CalculateMetadataHash(sourceChainSelector, destChainSelector, onRamp)
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

func (c OfframpContract) CalculateMessageHash(opts *bind.CallOpts, messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender []byte, receiver aptos.AccountAddress, onRamp []byte, data []byte, gasLimit *big.Int, sourcePoolAddresses [][]byte, destTokenAddresses []aptos.AccountAddress, destGasAmounts []uint32, extraDatas [][]byte, amounts []*big.Int) ([]byte, error) {
	module, function, typeTags, args, err := c.offrampEncoder.CalculateMessageHash(messageId, sourceChainSelector, destChainSelector, sequenceNumber, nonce, sender, receiver, onRamp, data, gasLimit, sourcePoolAddresses, destTokenAddresses, destGasAmounts, extraDatas, amounts)
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

func (c OfframpContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.offrampEncoder.Owner()
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

func (c OfframpContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.offrampEncoder.HasPendingTransfer()
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

func (c OfframpContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.offrampEncoder.PendingTransferFrom()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c OfframpContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.offrampEncoder.PendingTransferTo()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c OfframpContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.offrampEncoder.PendingTransferAccepted()
	if err != nil {
		return *new(*bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bool), err
	}

	var (
		r0 bind.StdOption[bool]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bool), err
	}
	return r0.Value(), nil
}

func (c OfframpContract) LatestConfigDetails(opts *bind.CallOpts, ocrPluginType byte) (module_ocr3_base.OCRConfig, error) {
	module, function, typeTags, args, err := c.offrampEncoder.LatestConfigDetails(ocrPluginType)
	if err != nil {
		return *new(module_ocr3_base.OCRConfig), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(module_ocr3_base.OCRConfig), err
	}

	var (
		r0 module_ocr3_base.OCRConfig
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(module_ocr3_base.OCRConfig), err
	}
	return r0, nil
}

// Entry Functions

func (c OfframpContract) Initialize(opts *bind.TransactOpts, chainSelector uint64, permissionlessExecutionThresholdSeconds uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.Initialize(chainSelector, permissionlessExecutionThresholdSeconds, sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnRamp)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) Execute(opts *bind.TransactOpts, reportContext [][]byte, report []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.Execute(reportContext, report)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) ManuallyExecute(opts *bind.TransactOpts, reportBytes []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.ManuallyExecute(reportBytes)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) Commit(opts *bind.TransactOpts, reportContext [][]byte, report []byte, signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.Commit(reportContext, report, signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) SetDynamicConfig(opts *bind.TransactOpts, permissionlessExecutionThresholdSeconds uint32) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.SetDynamicConfig(permissionlessExecutionThresholdSeconds)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) ApplySourceChainConfigUpdates(opts *bind.TransactOpts, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.ApplySourceChainConfigUpdates(sourceChainsSelector, sourceChainsIsEnabled, sourceChainsIsRMNVerificationDisabled, sourceChainsOnRamp)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c OfframpContract) SetOcr3Config(opts *bind.TransactOpts, configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.offrampEncoder.SetOcr3Config(configDigest, ocrPluginType, bigF, isSignatureVerificationEnabled, signers, transmitters)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type offrampEncoder struct {
	*bind.BoundContract
}

func (c offrampEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c offrampEncoder) GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address", nil, []string{}, []any{})
}

func (c offrampEncoder) GetExecutionState(sourceChainSelector uint64, sequenceNumber uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_execution_state", nil, []string{
		"u64",
		"u64",
	}, []any{
		sourceChainSelector,
		sequenceNumber,
	})
}

func (c offrampEncoder) GetLatestPriceSequenceNumber() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_latest_price_sequence_number", nil, []string{}, []any{})
}

func (c offrampEncoder) GetMerkleRoot(root []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_merkle_root", nil, []string{
		"vector<u8>",
	}, []any{
		root,
	})
}

func (c offrampEncoder) GetSourceChainConfig(sourceChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_source_chain_config", nil, []string{
		"u64",
	}, []any{
		sourceChainSelector,
	})
}

func (c offrampEncoder) GetAllSourceChainConfigs() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_all_source_chain_configs", nil, []string{}, []any{})
}

func (c offrampEncoder) GetStaticConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_static_config", nil, []string{}, []any{})
}

func (c offrampEncoder) GetDynamicConfig() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dynamic_config", nil, []string{}, []any{})
}

func (c offrampEncoder) CalculateMetadataHash(sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_metadata_hash", nil, []string{
		"u64",
		"u64",
		"vector<u8>",
	}, []any{
		sourceChainSelector,
		destChainSelector,
		onRamp,
	})
}

func (c offrampEncoder) CalculateMessageHash(messageId []byte, sourceChainSelector uint64, destChainSelector uint64, sequenceNumber uint64, nonce uint64, sender []byte, receiver aptos.AccountAddress, onRamp []byte, data []byte, gasLimit *big.Int, sourcePoolAddresses [][]byte, destTokenAddresses []aptos.AccountAddress, destGasAmounts []uint32, extraDatas [][]byte, amounts []*big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_message_hash", nil, []string{
		"vector<u8>",
		"u64",
		"u64",
		"u64",
		"u64",
		"vector<u8>",
		"address",
		"vector<u8>",
		"vector<u8>",
		"u256",
		"vector<vector<u8>>",
		"vector<address>",
		"vector<u32>",
		"vector<vector<u8>>",
		"vector<u256>",
	}, []any{
		messageId,
		sourceChainSelector,
		destChainSelector,
		sequenceNumber,
		nonce,
		sender,
		receiver,
		onRamp,
		data,
		gasLimit,
		sourcePoolAddresses,
		destTokenAddresses,
		destGasAmounts,
		extraDatas,
		amounts,
	})
}

func (c offrampEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c offrampEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c offrampEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c offrampEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c offrampEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c offrampEncoder) LatestConfigDetails(ocrPluginType byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("latest_config_details", nil, []string{
		"u8",
	}, []any{
		ocrPluginType,
	})
}

func (c offrampEncoder) Initialize(chainSelector uint64, permissionlessExecutionThresholdSeconds uint32, sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"u64",
		"u32",
		"vector<u64>",
		"vector<bool>",
		"vector<bool>",
		"vector<vector<u8>>",
	}, []any{
		chainSelector,
		permissionlessExecutionThresholdSeconds,
		sourceChainsSelector,
		sourceChainsIsEnabled,
		sourceChainsIsRMNVerificationDisabled,
		sourceChainsOnRamp,
	})
}

func (c offrampEncoder) Execute(reportContext [][]byte, report []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute", nil, []string{
		"vector<vector<u8>>",
		"vector<u8>",
	}, []any{
		reportContext,
		report,
	})
}

func (c offrampEncoder) ManuallyExecute(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("manually_execute", nil, []string{
		"vector<u8>",
	}, []any{
		reportBytes,
	})
}

func (c offrampEncoder) Commit(reportContext [][]byte, report []byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c offrampEncoder) SetDynamicConfig(permissionlessExecutionThresholdSeconds uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_dynamic_config", nil, []string{
		"u32",
	}, []any{
		permissionlessExecutionThresholdSeconds,
	})
}

func (c offrampEncoder) ApplySourceChainConfigUpdates(sourceChainsSelector []uint64, sourceChainsIsEnabled []bool, sourceChainsIsRMNVerificationDisabled []bool, sourceChainsOnRamp [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c offrampEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c offrampEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c offrampEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c offrampEncoder) SetOcr3Config(configDigest []byte, ocrPluginType byte, bigF byte, isSignatureVerificationEnabled bool, signers [][]byte, transmitters []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
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

func (c offrampEncoder) GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address_internal", nil, []string{}, []any{})
}

func (c offrampEncoder) CalculateMetadataHashInlined(sourceChainSelector uint64, destChainSelector uint64, onRamp []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_metadata_hash_inlined", nil, []string{
		"u64",
		"u64",
		"vector<u8>",
	}, []any{
		sourceChainSelector,
		destChainSelector,
		onRamp,
	})
}

func (c offrampEncoder) DeserializeCommitReport(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("deserialize_commit_report", nil, []string{
		"vector<u8>",
	}, []any{
		reportBytes,
	})
}

func (c offrampEncoder) DeserializeExecutionReport(reportBytes []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("deserialize_execution_report", nil, []string{
		"vector<u8>",
	}, []any{
		reportBytes,
	})
}

func (c offrampEncoder) CreateStaticConfig(chainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("create_static_config", nil, []string{
		"u64",
	}, []any{
		chainSelector,
	})
}

func (c offrampEncoder) CreateDynamicConfig(permissionlessExecutionThresholdSeconds uint32) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("create_dynamic_config", nil, []string{
		"u32",
	}, []any{
		permissionlessExecutionThresholdSeconds,
	})
}

func (c offrampEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}

func (c offrampEncoder) RegisterMCMSEntrypoint() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("register_mcms_entrypoint", nil, []string{}, []any{})
}
