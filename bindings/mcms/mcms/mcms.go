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

type MCMSInterface interface {
	SeenSignedHashes(opts *bind.CallOpts, multisig aptos.AccountAddress) (*bind.StdSimpleMap[[]byte, bool], error)
	ExpiringRootAndOpCount(opts *bind.CallOpts, multisig aptos.AccountAddress) ([]byte, uint64, uint64, error)
	RootMetadata(opts *bind.CallOpts, multisig aptos.AccountAddress) (RootMetadata, error)
	GetRootMetadata(opts *bind.CallOpts, role byte) (RootMetadata, error)
	GetOpCount(opts *bind.CallOpts, role byte) (uint64, error)
	GetRoot(opts *bind.CallOpts, role byte) ([]byte, uint64, error)
	GetConfig(opts *bind.CallOpts, role byte) (Config, error)
	Signers(opts *bind.CallOpts, multisig aptos.AccountAddress) (*bind.StdSimpleMap[[]byte, Signer], error)
	MultisigObject(opts *bind.CallOpts, role byte) (aptos.AccountAddress, error)
	NumGroups(opts *bind.CallOpts) (uint64, error)
	MaxNumSigners(opts *bind.CallOpts) (uint64, error)
	BypasserRole(opts *bind.CallOpts) (byte, error)
	CancellerRole(opts *bind.CallOpts) (byte, error)
	ProposerRole(opts *bind.CallOpts) (byte, error)
	TimelockRole(opts *bind.CallOpts) (byte, error)
	IsValidRole(opts *bind.CallOpts, role byte) (bool, error)
	ZeroHash(opts *bind.CallOpts) ([]byte, error)
	TimelockGetBlockedFunction(opts *bind.CallOpts, index uint64) (Function, error)
	TimelockIsOperation(opts *bind.CallOpts, id []byte) (bool, error)
	TimelockIsOperationPending(opts *bind.CallOpts, id []byte) (bool, error)
	TimelockIsOperationReady(opts *bind.CallOpts, id []byte) (bool, error)
	TimelockIsOperationDone(opts *bind.CallOpts, id []byte) (bool, error)
	TimelockGetTimestamp(opts *bind.CallOpts, id []byte) (uint64, error)
	TimelockMinDelay(opts *bind.CallOpts) (uint64, error)
	TimelockGetBlockedFunctions(opts *bind.CallOpts) ([]Function, error)
	TimelockGetBlockedFunctionsCount(opts *bind.CallOpts) (uint64, error)

	SetRoot(opts *bind.TransactOpts, role byte, root []byte, validUntil uint64, chainId *big.Int, multisigAddr aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (*api.PendingTransaction, error)
	Execute(opts *bind.TransactOpts, role byte, chainId *big.Int, multisigAddr aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, functionName string, data []byte, proof [][]byte) (*api.PendingTransaction, error)
	SetConfig(opts *bind.TransactOpts, role byte, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (*api.PendingTransaction, error)
	TimelockExecuteBatch(opts *bind.TransactOpts, targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSEncoder
}

type MCMSEncoder interface {
	SeenSignedHashes(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExpiringRootAndOpCount(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RootMetadata(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRootMetadata(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOpCount(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetRoot(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetConfig(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Signers(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MultisigObject(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	NumGroups() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MaxNumSigners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	BypasserRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CancellerRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ProposerRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsValidRole(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ZeroHash() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockGetBlockedFunction(index uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockIsOperation(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockIsOperationPending(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockIsOperationReady(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockIsOperationDone(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockGetTimestamp(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockMinDelay() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockGetBlockedFunctions() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockGetBlockedFunctionsCount() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetRoot(role byte, root []byte, validUntil uint64, chainId *big.Int, multisigAddr aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Execute(role byte, chainId *big.Int, multisigAddr aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, functionName string, data []byte, proof [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetConfig(role byte, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockExecuteBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CreateMultisig(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	EcdsaRecoverEvmAddr(ethSignedMessageHash []byte, signature []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DispatchToTimelock(role byte, functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	VerifyMerkleProof(proof [][]byte, root []byte, leaf []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ComputeEthMessageHash(root []byte, validUntil uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HashOpLeaf(domainSeparator []byte, op Op) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HashMetadataLeaf(metadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Role(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ChainId(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	RootMetadataMultisig(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PreOpCount(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PostOpCount(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	OverridePreviousRoot(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockScheduleBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte, delay uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockBeforeCall(id []byte, predecessor []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockAfterCall(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockBypasserExecuteBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockDispatch(target aptos.AccountAddress, moduleName string, functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockDispatchToSelf(functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockDispatchToAccount(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockDispatchToDeployer(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockDispatchToRegistry(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockCancel(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockUpdateMinDelay(newMinDelay uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockBlockFunction(target aptos.AccountAddress, moduleName string, functionName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TimelockUnblockFunction(target aptos.AccountAddress, moduleName string, functionName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CreateCalls(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HashOperationBatch(calls []Call, predecessor []byte, salt []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FunctionName(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ModuleName(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Target(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Data(call Call) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms","module":"mcms","name":"chain_id","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"compute_eth_message_hash","parameters":[{"name":"root","type":"vector\u003cu8\u003e"},{"name":"valid_until","type":"u64"}]},{"package":"mcms","module":"mcms","name":"create_calls","parameters":[{"name":"targets","type":"vector\u003caddress\u003e"},{"name":"module_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"function_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"datas","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms","name":"create_multisig","parameters":[{"name":"role","type":"u8"}]},{"package":"mcms","module":"mcms","name":"data","parameters":[{"name":"call","type":"Call"}]},{"package":"mcms","module":"mcms","name":"dispatch_to_timelock","parameters":[{"name":"role","type":"u8"},{"name":"function_name","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"ecdsa_recover_evm_addr","parameters":[{"name":"eth_signed_message_hash","type":"vector\u003cu8\u003e"},{"name":"signature","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"execute","parameters":[{"name":"role","type":"u8"},{"name":"chain_id","type":"u256"},{"name":"multisig_addr","type":"address"},{"name":"nonce","type":"u64"},{"name":"to","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function_name","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"proof","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms","name":"function_name","parameters":[{"name":"function","type":"Function"}]},{"package":"mcms","module":"mcms","name":"hash_metadata_leaf","parameters":[{"name":"metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"hash_op_leaf","parameters":[{"name":"domain_separator","type":"vector\u003cu8\u003e"},{"name":"op","type":"Op"}]},{"package":"mcms","module":"mcms","name":"hash_operation_batch","parameters":[{"name":"calls","type":"vector\u003cCall\u003e"},{"name":"predecessor","type":"vector\u003cu8\u003e"},{"name":"salt","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"module_name","parameters":[{"name":"function","type":"Function"}]},{"package":"mcms","module":"mcms","name":"override_previous_root","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"post_op_count","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"pre_op_count","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"role","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"root_metadata_multisig","parameters":[{"name":"root_metadata","type":"RootMetadata"}]},{"package":"mcms","module":"mcms","name":"set_config","parameters":[{"name":"role","type":"u8"},{"name":"signer_addresses","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"signer_groups","type":"vector\u003cu8\u003e"},{"name":"group_quorums","type":"vector\u003cu8\u003e"},{"name":"group_parents","type":"vector\u003cu8\u003e"},{"name":"clear_root","type":"bool"}]},{"package":"mcms","module":"mcms","name":"set_root","parameters":[{"name":"role","type":"u8"},{"name":"root","type":"vector\u003cu8\u003e"},{"name":"valid_until","type":"u64"},{"name":"chain_id","type":"u256"},{"name":"multisig_addr","type":"address"},{"name":"pre_op_count","type":"u64"},{"name":"post_op_count","type":"u64"},{"name":"override_previous_root","type":"bool"},{"name":"metadata_proof","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"signatures","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms","name":"target","parameters":[{"name":"function","type":"Function"}]},{"package":"mcms","module":"mcms","name":"timelock_after_call","parameters":[{"name":"id","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_before_call","parameters":[{"name":"id","type":"vector\u003cu8\u003e"},{"name":"predecessor","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_block_function","parameters":[{"name":"target","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function_name","type":"0x1::string::String"}]},{"package":"mcms","module":"mcms","name":"timelock_bypasser_execute_batch","parameters":[{"name":"targets","type":"vector\u003caddress\u003e"},{"name":"module_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"function_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"datas","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_cancel","parameters":[{"name":"id","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_dispatch","parameters":[{"name":"target","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function_name","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_dispatch_to_account","parameters":[{"name":"function_name_bytes","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_dispatch_to_deployer","parameters":[{"name":"function_name_bytes","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_dispatch_to_registry","parameters":[{"name":"function_name_bytes","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_dispatch_to_self","parameters":[{"name":"function_name","type":"0x1::string::String"},{"name":"data","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_execute_batch","parameters":[{"name":"targets","type":"vector\u003caddress\u003e"},{"name":"module_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"function_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"datas","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"predecessor","type":"vector\u003cu8\u003e"},{"name":"salt","type":"vector\u003cu8\u003e"}]},{"package":"mcms","module":"mcms","name":"timelock_schedule_batch","parameters":[{"name":"targets","type":"vector\u003caddress\u003e"},{"name":"module_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"function_names","type":"vector\u003c0x1::string::String\u003e"},{"name":"datas","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"predecessor","type":"vector\u003cu8\u003e"},{"name":"salt","type":"vector\u003cu8\u003e"},{"name":"delay","type":"u64"}]},{"package":"mcms","module":"mcms","name":"timelock_unblock_function","parameters":[{"name":"target","type":"address"},{"name":"module_name","type":"0x1::string::String"},{"name":"function_name","type":"0x1::string::String"}]},{"package":"mcms","module":"mcms","name":"timelock_update_min_delay","parameters":[{"name":"new_min_delay","type":"u64"}]},{"package":"mcms","module":"mcms","name":"verify_merkle_proof","parameters":[{"name":"proof","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"root","type":"vector\u003cu8\u003e"},{"name":"leaf","type":"vector\u003cu8\u003e"}]}]`

func NewMCMS(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSInterface {
	contract := bind.NewBoundContract(address, "mcms", "mcms", client)
	return MCMSContract{
		BoundContract: contract,
		mcmsEncoder:   mcmsEncoder{BoundContract: contract},
	}
}

// Constants
const (
	BYPASSER_ROLE                           byte   = 0
	CANCELLER_ROLE                          byte   = 1
	PROPOSER_ROLE                           byte   = 2
	TIMELOCK_ROLE                           byte   = 3
	MAX_ROLE                                byte   = 4
	NUM_GROUPS                              uint64 = 32
	MAX_NUM_SIGNERS                         uint64 = 200
	DONE_TIMESTAMP                          uint64 = 1
	E_ALREADY_SEEN_HASH                     uint64 = 1
	E_POST_OP_COUNT_REACHED                 uint64 = 2
	E_WRONG_CHAIN_ID                        uint64 = 3
	E_WRONG_MULTISIG                        uint64 = 4
	E_ROOT_EXPIRED                          uint64 = 5
	E_WRONG_NONCE                           uint64 = 6
	E_VALID_UNTIL_EXPIRED                   uint64 = 7
	E_INVALID_SIGNER                        uint64 = 8
	E_MISSING_CONFIG                        uint64 = 9
	E_INSUFFICIENT_SIGNERS                  uint64 = 10
	E_PROOF_CANNOT_BE_VERIFIED              uint64 = 11
	E_PENDING_OPS                           uint64 = 12
	E_WRONG_PRE_OP_COUNT                    uint64 = 13
	E_WRONG_POST_OP_COUNT                   uint64 = 14
	E_INVALID_NUM_SIGNERS                   uint64 = 15
	E_SIGNER_GROUPS_LEN_MISMATCH            uint64 = 16
	E_INVALID_GROUP_QUORUM_LEN              uint64 = 17
	E_INVALID_GROUP_PARENTS_LEN             uint64 = 18
	E_OUT_OF_BOUNDS_GROUP                   uint64 = 19
	E_GROUP_TREE_NOT_WELL_FORMED            uint64 = 20
	E_SIGNER_IN_DISABLED_GROUP              uint64 = 21
	E_OUT_OF_BOUNDS_GROUP_QUORUM            uint64 = 22
	E_SIGNER_ADDR_MUST_BE_INCREASING        uint64 = 23
	E_INVALID_SIGNER_ADDR_LEN               uint64 = 24
	E_UNKNOWN_MCMS_MODULE_FUNCTION          uint64 = 25
	E_UNKNOWN_FRAMEWORK_MODULE_FUNCTION     uint64 = 26
	E_UNKNOWN_FRAMEWORK_MODULE              uint64 = 27
	E_SELF_CALL_ROLE_MISMATCH               uint64 = 28
	E_NOT_BYPASSER_ROLE                     uint64 = 29
	E_INVALID_ROLE                          uint64 = 30
	E_NOT_AUTHORIZED_ROLE                   uint64 = 31
	E_NOT_AUTHORIZED                        uint64 = 32
	E_OPERATION_ALREADY_SCHEDULED           uint64 = 33
	E_INSUFFICIENT_DELAY                    uint64 = 34
	E_OPERATION_NOT_READY                   uint64 = 35
	E_MISSING_DEPENDENCY                    uint64 = 36
	E_OPERATION_CANNOT_BE_CANCELLED         uint64 = 37
	E_FUNCTION_BLOCKED                      uint64 = 38
	E_INVALID_INDEX                         uint64 = 39
	E_UNKNOWN_MCMS_ACCOUNT_MODULE_FUNCTION  uint64 = 40
	E_UNKNOWN_MCMS_DEPLOYER_MODULE_FUNCTION uint64 = 41
	E_UNKNOWN_MCMS_REGISTRY_MODULE_FUNCTION uint64 = 42
	E_INVALID_PARAMETERS                    uint64 = 43
	E_INVALID_SIGNATURE_LEN                 uint64 = 44
	E_INVALID_V_SIGNATURE                   uint64 = 45
	E_FAILED_ECDSA_RECOVER                  uint64 = 46
	E_INVALID_MODULE_NAME                   uint64 = 47
	E_UNKNOWN_MCMS_TIMELOCK_FUNCTION        uint64 = 48
	E_INVALID_ROOT_LEN                      uint64 = 49
	E_NOT_CANCELLER_ROLE                    uint64 = 50
	E_NOT_TIMELOCK_ROLE                     uint64 = 51
	E_UNKNOWN_MCMS_MODULE                   uint64 = 52
)

// Structs

type MultisigState struct {
	Bypasser  bind.StdObject `move:"aptos_framework::object::Object"`
	Canceller bind.StdObject `move:"aptos_framework::object::Object"`
	Proposer  bind.StdObject `move:"aptos_framework::object::Object"`
}

type Multisig struct {
	Signers                *bind.StdSimpleMap[[]byte, Signer] `move:"std::simple_map::SimpleMap<vector<u8>,Signer>"`
	Config                 Config                             `move:"Config"`
	SeenSignedHashes       *bind.StdSimpleMap[[]byte, bool]   `move:"std::simple_map::SimpleMap<vector<u8>,bool>"`
	ExpiringRootAndOpCount ExpiringRootAndOpCount             `move:"ExpiringRootAndOpCount"`
	RootMetadata           RootMetadata                       `move:"RootMetadata"`
}

type Op struct {
	Role         byte                 `move:"u8"`
	ChainId      *big.Int             `move:"u256"`
	Multisig     aptos.AccountAddress `move:"address"`
	Nonce        uint64               `move:"u64"`
	To           aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
	Data         []byte               `move:"vector<u8>"`
}

type RootMetadata struct {
	Role                 byte                 `move:"u8"`
	ChainId              *big.Int             `move:"u256"`
	Multisig             aptos.AccountAddress `move:"address"`
	PreOpCount           uint64               `move:"u64"`
	PostOpCount          uint64               `move:"u64"`
	OverridePreviousRoot bool                 `move:"bool"`
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

type MultisigStateInitialized struct {
	Bypasser  bind.StdObject `move:"aptos_framework::object::Object"`
	Canceller bind.StdObject `move:"aptos_framework::object::Object"`
	Proposer  bind.StdObject `move:"aptos_framework::object::Object"`
}

type ConfigSet struct {
	Role          byte   `move:"u8"`
	Config        Config `move:"Config"`
	IsRootCleared bool   `move:"bool"`
}

type NewRoot struct {
	Role       byte         `move:"u8"`
	Root       []byte       `move:"vector<u8>"`
	ValidUntil uint64       `move:"u64"`
	Metadata   RootMetadata `move:"RootMetadata"`
}

type OpExecuted struct {
	Role         byte                 `move:"u8"`
	ChainId      *big.Int             `move:"u256"`
	Multisig     aptos.AccountAddress `move:"address"`
	Nonce        uint64               `move:"u64"`
	To           aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
	Data         []byte               `move:"vector<u8>"`
}

type Timelock struct {
	MinDelay uint64 `move:"u64"`
}

type Call struct {
	Function Function `move:"Function"`
	Data     []byte   `move:"vector<u8>"`
}

type Function struct {
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
}

type TimelockInitialized struct {
	MinDelay uint64 `move:"u64"`
}

type BypasserCallExecuted struct {
	Index        uint64               `move:"u64"`
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
	Data         []byte               `move:"vector<u8>"`
}

type Cancelled struct {
	Id []byte `move:"vector<u8>"`
}

type CallScheduled struct {
	Id           []byte               `move:"vector<u8>"`
	Index        uint64               `move:"u64"`
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
	Data         []byte               `move:"vector<u8>"`
	Predecessor  []byte               `move:"vector<u8>"`
	Salt         []byte               `move:"vector<u8>"`
	Delay        uint64               `move:"u64"`
}

type CallExecuted struct {
	Id           []byte               `move:"vector<u8>"`
	Index        uint64               `move:"u64"`
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
	Data         []byte               `move:"vector<u8>"`
}

type UpdateMinDelay struct {
	OldMinDelay uint64 `move:"u64"`
	NewMinDelay uint64 `move:"u64"`
}

type FunctionBlocked struct {
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
}

type FunctionUnblocked struct {
	Target       aptos.AccountAddress `move:"address"`
	ModuleName   string               `move:"0x1::string::String"`
	FunctionName string               `move:"0x1::string::String"`
}

type MCMSContract struct {
	*bind.BoundContract
	mcmsEncoder
}

var _ MCMSInterface = MCMSContract{}

func (c MCMSContract) Encoder() MCMSEncoder {
	return c.mcmsEncoder
}

// View Functions

func (c MCMSContract) SeenSignedHashes(opts *bind.CallOpts, multisig aptos.AccountAddress) (*bind.StdSimpleMap[[]byte, bool], error) {
	module, function, typeTags, args, err := c.mcmsEncoder.SeenSignedHashes(multisig)
	if err != nil {
		return *new(*bind.StdSimpleMap[[]byte, bool]), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bind.StdSimpleMap[[]byte, bool]), err
	}

	var (
		r0 *bind.StdSimpleMap[[]byte, bool]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bind.StdSimpleMap[[]byte, bool]), err
	}
	return r0, nil
}

func (c MCMSContract) ExpiringRootAndOpCount(opts *bind.CallOpts, multisig aptos.AccountAddress) ([]byte, uint64, uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.ExpiringRootAndOpCount(multisig)
	if err != nil {
		return *new([]byte), *new(uint64), *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]byte), *new(uint64), *new(uint64), err
	}

	var (
		r0 []byte
		r1 uint64
		r2 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0, &r1, &r2); err != nil {
		return *new([]byte), *new(uint64), *new(uint64), err
	}
	return r0, r1, r2, nil
}

func (c MCMSContract) RootMetadata(opts *bind.CallOpts, multisig aptos.AccountAddress) (RootMetadata, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.RootMetadata(multisig)
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

func (c MCMSContract) GetRootMetadata(opts *bind.CallOpts, role byte) (RootMetadata, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetRootMetadata(role)
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

func (c MCMSContract) GetOpCount(opts *bind.CallOpts, role byte) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetOpCount(role)
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

func (c MCMSContract) GetRoot(opts *bind.CallOpts, role byte) ([]byte, uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetRoot(role)
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

func (c MCMSContract) GetConfig(opts *bind.CallOpts, role byte) (Config, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.GetConfig(role)
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

func (c MCMSContract) Signers(opts *bind.CallOpts, multisig aptos.AccountAddress) (*bind.StdSimpleMap[[]byte, Signer], error) {
	module, function, typeTags, args, err := c.mcmsEncoder.Signers(multisig)
	if err != nil {
		return *new(*bind.StdSimpleMap[[]byte, Signer]), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bind.StdSimpleMap[[]byte, Signer]), err
	}

	var (
		r0 *bind.StdSimpleMap[[]byte, Signer]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bind.StdSimpleMap[[]byte, Signer]), err
	}
	return r0, nil
}

func (c MCMSContract) MultisigObject(opts *bind.CallOpts, role byte) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.MultisigObject(role)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 bind.StdObject
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0.Address(), nil
}

func (c MCMSContract) NumGroups(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.NumGroups()
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

func (c MCMSContract) MaxNumSigners(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.MaxNumSigners()
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

func (c MCMSContract) BypasserRole(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.BypasserRole()
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

func (c MCMSContract) CancellerRole(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.CancellerRole()
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

func (c MCMSContract) ProposerRole(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.ProposerRole()
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

func (c MCMSContract) TimelockRole(opts *bind.CallOpts) (byte, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockRole()
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

func (c MCMSContract) IsValidRole(opts *bind.CallOpts, role byte) (bool, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.IsValidRole(role)
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

func (c MCMSContract) ZeroHash(opts *bind.CallOpts) ([]byte, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.ZeroHash()
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

func (c MCMSContract) TimelockGetBlockedFunction(opts *bind.CallOpts, index uint64) (Function, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockGetBlockedFunction(index)
	if err != nil {
		return *new(Function), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(Function), err
	}

	var (
		r0 Function
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(Function), err
	}
	return r0, nil
}

func (c MCMSContract) TimelockIsOperation(opts *bind.CallOpts, id []byte) (bool, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockIsOperation(id)
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

func (c MCMSContract) TimelockIsOperationPending(opts *bind.CallOpts, id []byte) (bool, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockIsOperationPending(id)
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

func (c MCMSContract) TimelockIsOperationReady(opts *bind.CallOpts, id []byte) (bool, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockIsOperationReady(id)
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

func (c MCMSContract) TimelockIsOperationDone(opts *bind.CallOpts, id []byte) (bool, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockIsOperationDone(id)
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

func (c MCMSContract) TimelockGetTimestamp(opts *bind.CallOpts, id []byte) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockGetTimestamp(id)
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

func (c MCMSContract) TimelockMinDelay(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockMinDelay()
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

func (c MCMSContract) TimelockGetBlockedFunctions(opts *bind.CallOpts) ([]Function, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockGetBlockedFunctions()
	if err != nil {
		return *new([]Function), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]Function), err
	}

	var (
		r0 []Function
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]Function), err
	}
	return r0, nil
}

func (c MCMSContract) TimelockGetBlockedFunctionsCount(opts *bind.CallOpts) (uint64, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockGetBlockedFunctionsCount()
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

// Entry Functions

func (c MCMSContract) SetRoot(opts *bind.TransactOpts, role byte, root []byte, validUntil uint64, chainId *big.Int, multisigAddr aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.SetRoot(role, root, validUntil, chainId, multisigAddr, preOpCount, postOpCount, overridePreviousRoot, metadataProof, signatures)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSContract) Execute(opts *bind.TransactOpts, role byte, chainId *big.Int, multisigAddr aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, functionName string, data []byte, proof [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.Execute(role, chainId, multisigAddr, nonce, to, moduleName, functionName, data, proof)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSContract) SetConfig(opts *bind.TransactOpts, role byte, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.SetConfig(role, signerAddresses, signerGroups, groupQuorums, groupParents, clearRoot)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c MCMSContract) TimelockExecuteBatch(opts *bind.TransactOpts, targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.mcmsEncoder.TimelockExecuteBatch(targets, moduleNames, functionNames, datas, predecessor, salt)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type mcmsEncoder struct {
	*bind.BoundContract
}

func (c mcmsEncoder) SeenSignedHashes(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("seen_signed_hashes", nil, []string{
		"address",
	}, []any{
		multisig,
	})
}

func (c mcmsEncoder) ExpiringRootAndOpCount(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("expiring_root_and_op_count", nil, []string{
		"address",
	}, []any{
		multisig,
	})
}

func (c mcmsEncoder) RootMetadata(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("root_metadata", nil, []string{
		"address",
	}, []any{
		multisig,
	})
}

func (c mcmsEncoder) GetRootMetadata(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_root_metadata", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) GetOpCount(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_op_count", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) GetRoot(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_root", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) GetConfig(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_config", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) Signers(multisig aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("signers", nil, []string{
		"address",
	}, []any{
		multisig,
	})
}

func (c mcmsEncoder) MultisigObject(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("multisig_object", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) NumGroups() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("num_groups", nil, []string{}, []any{})
}

func (c mcmsEncoder) MaxNumSigners() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("max_num_signers", nil, []string{}, []any{})
}

func (c mcmsEncoder) BypasserRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("bypasser_role", nil, []string{}, []any{})
}

func (c mcmsEncoder) CancellerRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("canceller_role", nil, []string{}, []any{})
}

func (c mcmsEncoder) ProposerRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("proposer_role", nil, []string{}, []any{})
}

func (c mcmsEncoder) TimelockRole() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_role", nil, []string{}, []any{})
}

func (c mcmsEncoder) IsValidRole(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_valid_role", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) ZeroHash() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("zero_hash", nil, []string{}, []any{})
}

func (c mcmsEncoder) TimelockGetBlockedFunction(index uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_get_blocked_function", nil, []string{
		"u64",
	}, []any{
		index,
	})
}

func (c mcmsEncoder) TimelockIsOperation(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_is_operation", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockIsOperationPending(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_is_operation_pending", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockIsOperationReady(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_is_operation_ready", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockIsOperationDone(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_is_operation_done", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockGetTimestamp(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_get_timestamp", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockMinDelay() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_min_delay", nil, []string{}, []any{})
}

func (c mcmsEncoder) TimelockGetBlockedFunctions() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_get_blocked_functions", nil, []string{}, []any{})
}

func (c mcmsEncoder) TimelockGetBlockedFunctionsCount() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_get_blocked_functions_count", nil, []string{}, []any{})
}

func (c mcmsEncoder) SetRoot(role byte, root []byte, validUntil uint64, chainId *big.Int, multisigAddr aptos.AccountAddress, preOpCount uint64, postOpCount uint64, overridePreviousRoot bool, metadataProof [][]byte, signatures [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_root", nil, []string{
		"u8",
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
		role,
		root,
		validUntil,
		chainId,
		multisigAddr,
		preOpCount,
		postOpCount,
		overridePreviousRoot,
		metadataProof,
		signatures,
	})
}

func (c mcmsEncoder) Execute(role byte, chainId *big.Int, multisigAddr aptos.AccountAddress, nonce uint64, to aptos.AccountAddress, moduleName string, functionName string, data []byte, proof [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute", nil, []string{
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
		multisigAddr,
		nonce,
		to,
		moduleName,
		functionName,
		data,
		proof,
	})
}

func (c mcmsEncoder) SetConfig(role byte, signerAddresses [][]byte, signerGroups []byte, groupQuorums []byte, groupParents []byte, clearRoot bool) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_config", nil, []string{
		"u8",
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<u8>",
		"vector<u8>",
		"bool",
	}, []any{
		role,
		signerAddresses,
		signerGroups,
		groupQuorums,
		groupParents,
		clearRoot,
	})
}

func (c mcmsEncoder) TimelockExecuteBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_execute_batch", nil, []string{
		"vector<address>",
		"vector<0x1::string::String>",
		"vector<0x1::string::String>",
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		targets,
		moduleNames,
		functionNames,
		datas,
		predecessor,
		salt,
	})
}

func (c mcmsEncoder) CreateMultisig(role byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("create_multisig", nil, []string{
		"u8",
	}, []any{
		role,
	})
}

func (c mcmsEncoder) EcdsaRecoverEvmAddr(ethSignedMessageHash []byte, signature []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ecdsa_recover_evm_addr", nil, []string{
		"vector<u8>",
		"vector<u8>",
	}, []any{
		ethSignedMessageHash,
		signature,
	})
}

func (c mcmsEncoder) DispatchToTimelock(role byte, functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("dispatch_to_timelock", nil, []string{
		"u8",
		"0x1::string::String",
		"vector<u8>",
	}, []any{
		role,
		functionName,
		data,
	})
}

func (c mcmsEncoder) VerifyMerkleProof(proof [][]byte, root []byte, leaf []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("verify_merkle_proof", nil, []string{
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		proof,
		root,
		leaf,
	})
}

func (c mcmsEncoder) ComputeEthMessageHash(root []byte, validUntil uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("compute_eth_message_hash", nil, []string{
		"vector<u8>",
		"u64",
	}, []any{
		root,
		validUntil,
	})
}

func (c mcmsEncoder) HashOpLeaf(domainSeparator []byte, op Op) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("hash_op_leaf", nil, []string{
		"vector<u8>",
		"Op",
	}, []any{
		domainSeparator,
		op,
	})
}

func (c mcmsEncoder) HashMetadataLeaf(metadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("hash_metadata_leaf", nil, []string{
		"RootMetadata",
	}, []any{
		metadata,
	})
}

func (c mcmsEncoder) Role(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("role", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) ChainId(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("chain_id", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) RootMetadataMultisig(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("root_metadata_multisig", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) PreOpCount(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pre_op_count", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) PostOpCount(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("post_op_count", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) OverridePreviousRoot(rootMetadata RootMetadata) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("override_previous_root", nil, []string{
		"RootMetadata",
	}, []any{
		rootMetadata,
	})
}

func (c mcmsEncoder) TimelockScheduleBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte, predecessor []byte, salt []byte, delay uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_schedule_batch", nil, []string{
		"vector<address>",
		"vector<0x1::string::String>",
		"vector<0x1::string::String>",
		"vector<vector<u8>>",
		"vector<u8>",
		"vector<u8>",
		"u64",
	}, []any{
		targets,
		moduleNames,
		functionNames,
		datas,
		predecessor,
		salt,
		delay,
	})
}

func (c mcmsEncoder) TimelockBeforeCall(id []byte, predecessor []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_before_call", nil, []string{
		"vector<u8>",
		"vector<u8>",
	}, []any{
		id,
		predecessor,
	})
}

func (c mcmsEncoder) TimelockAfterCall(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_after_call", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockBypasserExecuteBatch(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_bypasser_execute_batch", nil, []string{
		"vector<address>",
		"vector<0x1::string::String>",
		"vector<0x1::string::String>",
		"vector<vector<u8>>",
	}, []any{
		targets,
		moduleNames,
		functionNames,
		datas,
	})
}

func (c mcmsEncoder) TimelockDispatch(target aptos.AccountAddress, moduleName string, functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_dispatch", nil, []string{
		"address",
		"0x1::string::String",
		"0x1::string::String",
		"vector<u8>",
	}, []any{
		target,
		moduleName,
		functionName,
		data,
	})
}

func (c mcmsEncoder) TimelockDispatchToSelf(functionName string, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_dispatch_to_self", nil, []string{
		"0x1::string::String",
		"vector<u8>",
	}, []any{
		functionName,
		data,
	})
}

func (c mcmsEncoder) TimelockDispatchToAccount(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_dispatch_to_account", nil, []string{
		"vector<u8>",
		"vector<u8>",
	}, []any{
		functionNameBytes,
		data,
	})
}

func (c mcmsEncoder) TimelockDispatchToDeployer(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_dispatch_to_deployer", nil, []string{
		"vector<u8>",
		"vector<u8>",
	}, []any{
		functionNameBytes,
		data,
	})
}

func (c mcmsEncoder) TimelockDispatchToRegistry(functionNameBytes []byte, data []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_dispatch_to_registry", nil, []string{
		"vector<u8>",
		"vector<u8>",
	}, []any{
		functionNameBytes,
		data,
	})
}

func (c mcmsEncoder) TimelockCancel(id []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_cancel", nil, []string{
		"vector<u8>",
	}, []any{
		id,
	})
}

func (c mcmsEncoder) TimelockUpdateMinDelay(newMinDelay uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_update_min_delay", nil, []string{
		"u64",
	}, []any{
		newMinDelay,
	})
}

func (c mcmsEncoder) TimelockBlockFunction(target aptos.AccountAddress, moduleName string, functionName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_block_function", nil, []string{
		"address",
		"0x1::string::String",
		"0x1::string::String",
	}, []any{
		target,
		moduleName,
		functionName,
	})
}

func (c mcmsEncoder) TimelockUnblockFunction(target aptos.AccountAddress, moduleName string, functionName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("timelock_unblock_function", nil, []string{
		"address",
		"0x1::string::String",
		"0x1::string::String",
	}, []any{
		target,
		moduleName,
		functionName,
	})
}

func (c mcmsEncoder) CreateCalls(targets []aptos.AccountAddress, moduleNames []string, functionNames []string, datas [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("create_calls", nil, []string{
		"vector<address>",
		"vector<0x1::string::String>",
		"vector<0x1::string::String>",
		"vector<vector<u8>>",
	}, []any{
		targets,
		moduleNames,
		functionNames,
		datas,
	})
}

func (c mcmsEncoder) HashOperationBatch(calls []Call, predecessor []byte, salt []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("hash_operation_batch", nil, []string{
		"vector<Call>",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		calls,
		predecessor,
		salt,
	})
}

func (c mcmsEncoder) FunctionName(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("function_name", nil, []string{
		"Function",
	}, []any{
		function,
	})
}

func (c mcmsEncoder) ModuleName(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("module_name", nil, []string{
		"Function",
	}, []any{
		function,
	})
}

func (c mcmsEncoder) Target(function Function) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("target", nil, []string{
		"Function",
	}, []any{
		function,
	})
}

func (c mcmsEncoder) Data(call Call) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("data", nil, []string{
		"Call",
	}, []any{
		call,
	})
}
