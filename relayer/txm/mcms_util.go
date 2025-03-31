package txm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type TimelockOperation struct {
	Target       aptos.AccountAddress
	ModuleName   string
	FunctionName string
	Data         []byte
}

type SignerConfig struct {
	Addresses    [][]byte
	Groups       []uint8
	GroupQuorums []uint8
	GroupParents []uint8
}

// UnwrapObject unwraps an object from the data returned by client.View
func UnwrapObject(val any) (address *aptos.AccountAddress, err error) {
	// First unwrap outer array
	outerArray, ok := val.([]any)
	if !ok || len(outerArray) == 0 {
		err = errors.New("bad view return from node, expected outer array")
		return
	}

	// Get the object containing the inner field
	inner, ok := outerArray[0].(map[string]any)
	if !ok {
		err = errors.New("bad view return from node, could not unwrap object")
		return
	}

	addressString, ok := inner["inner"].(string)
	if !ok {
		err = errors.New("bad view return from node, inner field not a string")
		return
	}

	address = &aptos.AccountAddress{}
	err = address.ParseStringRelaxed(addressString)
	return
}

func createViewPayload(mcmsAddress string, module string, function string, argTypes []aptos.TypeTag, args [][]byte) *aptos.ViewPayload {
	addr := &aptos.AccountAddress{}
	err := addr.ParseStringRelaxed(mcmsAddress)
	if err != nil {
		panic(err)
	}
	return &aptos.ViewPayload{
		Module: aptos.ModuleId{
			Address: *addr,
			Name:    module,
		},
		Function: function,
		ArgTypes: argTypes,
		Args:     args,
	}
}

// generateSigners creates a specified number of signers with sorted addresses
func generateSigners(t *testing.T, count int) []Signer {
	signers := make([]Signer, count)
	for i := 0; i < count; i++ {
		privateKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		signers[i] = Signer{
			address:    crypto.PubkeyToAddress(privateKey.PublicKey).Bytes(),
			privateKey: privateKey,
		}
	}

	// Sort signers by address as required by the module
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i].address, signers[j].address) < 0
	})

	return signers
}

// serializeSetConfig serializes the parameters for set_config
func serializeSetConfig(role uint8, config SignerConfig) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// role: u8
		ser.U8(role)

		// signer_addresses: vector<vector<u8>>
		// Add one less signer than NUM_GROUPS
		ser.Uleb128(uint32(len(config.Addresses)))
		for _, addr := range config.Addresses {
			ser.WriteBytes(addr)
		}

		// signer_groups: vector<u8>
		ser.Uleb128(uint32(len(config.Groups)))
		for _, group := range config.Groups {
			ser.U8(group)
		}

		// group_quorums: vector<u8>
		ser.Uleb128(uint32(len(config.GroupQuorums)))
		for _, quorum := range config.GroupQuorums {
			ser.U8(quorum)
		}

		// group_parents: vector<u8>
		ser.Uleb128(uint32(len(config.GroupParents)))
		for _, parent := range config.GroupParents {
			ser.U8(parent)
		}

		// clear_root: bool
		ser.Bool(true)
	})
}

func setupInitialConfigAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, role uint8, signers []Signer, deployerAddress string, deployerPublicKeyHex string,
	clearRoot bool,
) {
	NUM_GROUPS := 32
	signerAddresses := [][]byte{}
	signerGroups := []uint8{}
	groupQuorums := make([]uint8, NUM_GROUPS)
	groupParents := make([]uint8, NUM_GROUPS)

	// Addresses are already sorted
	for _, signer := range signers {
		signerAddresses = append(signerAddresses, signer.address)
		signerGroups = append(signerGroups, 0)
	}
	groupQuorums[0] = 2

	logger.Debugw("deployerAddress", "deployerAddress", deployerAddress)
	logger.Debugw("deployerPublicKeyHex", "deployerPublicKeyHex", deployerPublicKeyHex)

	setConfigId := uuid.New().String()
	err := txm.Enqueue(
		setConfigId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAddress+"::mcms::set_config",
		[]string{},
		[]string{"u8", "vector<vector<u8>>", "vector<u8>", "vector<u8>", "vector<u8>", "bool"},
		[]any{
			role,
			signerAddresses,
			signerGroups,
			groupQuorums,
			groupParents,
			clearRoot,
		},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	logger.Infow("waiting for txmId setConfigId to be created...", "setConfigId", setConfigId)
	waitForTxmId(t, txm, setConfigId, time.Second*30)
}

// transferOwnership transfers ownership to self
func transferOwnership(t *testing.T, txm *AptosTxm, deployerAddress, deployerPublicKeyHex string) {
	transferOwnershipId := uuid.New().String()
	err := txm.Enqueue(
		transferOwnershipId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAddress+"::mcms_account::transfer_ownership_to_self",
		[]string{},
		[]string{},
		[]any{},
		true,
	)
	require.NoError(t, err)
	waitForTxmId(t, txm, transferOwnershipId, time.Second*30)
}

func getMultisigForRole(t *testing.T, mcmsAddress string, client *aptos.NodeClient, role uint8) aptos.AccountAddress {
	paramValues := [][]byte{}
	typeTag, err := CreateTypeTag("u8")
	require.NoError(t, err)
	bcsValue, err := CreateBcsValue(typeTag, role)
	require.NoError(t, err)
	paramValues = append(paramValues, bcsValue)

	viewPayload := createViewPayload(mcmsAddress, "mcms", "multisig_object", []aptos.TypeTag{}, paramValues)
	data, err := client.View(viewPayload)
	require.NoError(t, err)

	addr, err := UnwrapObject(data)
	require.NoError(t, err)
	return *addr
}

func executeBatchOperations(
	t *testing.T, txm *AptosTxm, mcmsAddress string, deployerAddress string, deployerPublicKeyHex string,
	ops []TimelockOperation, predecessor []byte, salt []byte) string {
	// Serialize vectors separately
	targets := make([]aptos.AccountAddress, len(ops))
	moduleNames := make([]string, len(ops))
	functionNames := make([]string, len(ops))
	datas := make([][]byte, len(ops))

	for i, op := range ops {
		targets[i] = op.Target
		moduleNames[i] = op.ModuleName
		functionNames[i] = op.FunctionName
		datas[i] = op.Data
	}

	txId := uuid.New().String()
	err := txm.Enqueue(
		txId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAddress+"::mcms::timelock_execute_batch",
		[]string{},
		[]string{
			"vector<address>",             // targets
			"vector<0x1::string::String>", // module_names
			"vector<0x1::string::String>", // function_names
			"vector<vector<u8>>",          // datas
			"vector<u8>",                  // predecessor
			"vector<u8>",                  // salt
		},
		[]any{
			targets,
			moduleNames,
			functionNames,
			datas,
			predecessor,
			salt,
		},
		true,
	)
	require.NoError(t, err)
	return txId
}

func writeAddress(ser *bcs.Serializer, addr aptos.AccountAddress) {
	ser.FixedBytes(addr[:])
}

func serializeScheduleBatchParams(ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// Serialize targets vector
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			writeAddress(ser, op.Target)
		}

		// Write module names
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteString(op.ModuleName)
		}

		// Write function names
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteString(op.FunctionName)
		}

		// Write data
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteBytes(op.Data)
		}

		ser.WriteBytes(predecessor)
		ser.WriteBytes(salt)
		ser.U64(delay)
	})
}

func serializeStageCodeChunkParams(metadata []byte, indices []uint16, chunks [][]byte, seed []byte) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteBytes(metadata)

		// Serialize indices
		ser.Uleb128(uint32(len(indices)))
		for _, idx := range indices {
			ser.U16(idx)
		}

		// Serialize chunks
		ser.Uleb128(uint32(len(chunks)))
		for _, chunk := range chunks {
			ser.WriteBytes(chunk)
		}

		ser.WriteBytes(seed)
	})
}

func timelockOpsToOp(
	tlOps []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, mcmsAccount aptos.AccountAddress, getNextNonce func() uint64) Op {

	// Serialize all operations at once for schedule_batch
	serializedData, err := serializeScheduleBatchParams(tlOps, predecessor, salt, delay)
	if err != nil {
		panic(fmt.Sprintf("failed to serialize operations: %v", err))
	}

	// Create a single Op that includes all operations
	op := Op{
		Role:         role,
		ChainID:      chainId,
		MultiSig:     mcmsAccount,
		Nonce:        getNextNonce(),
		To:           mcmsAccount,
		ModuleName:   "mcms",
		FunctionName: "timelock_schedule_batch",
		Data:         serializedData,
	}

	return op
}

// Create multiple operations and execute them one by one
func timelockOpToMulitpleOps(tlOps []TimelockOperation, predecessor []byte, salt []byte, delay uint64, role uint8, chainId *big.Int) []Op {
	ops := make([]Op, len(tlOps))

	for i, tlOp := range tlOps {
		// For each operation, serialize its parameters individually
		serializedData, err := serializeScheduleBatchParams([]TimelockOperation{tlOp}, predecessor, salt, delay)
		if err != nil {
			panic(fmt.Sprintf("failed to serialize operation: %v", err))
		}

		ops[i] = Op{
			Role:         role,
			ChainID:      chainId,
			MultiSig:     mcmsAccount,
			Nonce:        getNextNonce(),
			To:           mcmsAccount,
			ModuleName:   "mcms",
			FunctionName: "timelock_schedule_batch",
			Data:         serializedData,
		}
	}
	return ops
}

// scheduleSingleOperationAsDeployer schedules a single operation through MCMS
// This function is intended for scheduling a single operation only.
// For batching multiple operations, use scheduleBatchOperationsAsDeployer instead.
func scheduleSingleOperationAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, mcmsAccount aptos.AccountAddress, deployerAddress string,
	deployerPublicKeyHex string, ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, nonce uint64, proof [][32]byte,
) string {
	if len(ops) != 1 {
		panic("scheduleSingleOperationAsDeployer expects exactly one operation")
	}

	// Create the Op struct to compute its hash - must match EXACTLY what was used in the Merkle tree
	// This must match the format used in timelockOpsToOps when setting the root
	serializedData, err := serializeScheduleBatchParams([]TimelockOperation{ops[0]}, predecessor, salt, delay)
	require.NoError(t, err)

	op := Op{
		Role:         role,
		ChainID:      chainId,
		MultiSig:     mcmsAccount,
		Nonce:        nonce,
		To:           mcmsAccount,
		ModuleName:   "mcms",
		FunctionName: "timelock_schedule_batch",
		Data:         serializedData,
	}

	// Log the operation details
	logger.Debugw("Operation details",
		"role", op.Role,
		"chainId", op.ChainID,
		"multisig", op.MultiSig.String(),
		"nonce", op.Nonce,
		"to", op.To.String(),
		"moduleName", op.ModuleName,
		"functionName", op.FunctionName,
		"data", hex.EncodeToString(op.Data),
	)

	// Compute and log the leaf hash
	leafHash := hashOp(&op)
	logger.Debugw("Leaf hash", "value", hex.EncodeToString(leafHash[:]))

	// Log each proof element
	for i, p := range proof {
		logger.Debugw("Proof element", "index", i, "value", hex.EncodeToString(p[:]))
	}

	// Verify and log each step of the proof computation
	computedHash := leafHash
	for i, p := range proof {
		computedHash = hashPair(computedHash, p)
		logger.Debugw("Intermediate hash", "step", i, "value", hex.EncodeToString(computedHash[:]))
	}

	txId := uuid.New().String()
	err = txm.Enqueue(
		txId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAccount.String()+"::mcms::execute",
		[]string{},
		[]string{
			"u8",                  // role
			"u256",                // chainId
			"address",             // multisig
			"u64",                 // nonce
			"address",             // to
			"0x1::string::String", // moduleName
			"0x1::string::String", // function
			"vector<u8>",          // data
			"vector<vector<u8>>",  // proof
		},
		[]any{
			op.Role,
			op.ChainID,
			op.MultiSig,
			op.Nonce,
			op.To,
			op.ModuleName,
			op.FunctionName,
			op.Data,
			proof[:],
		},
		true,
	)
	require.NoError(t, err)

	waitForTxmId(t, txm, txId, time.Second*30)

	return txId
}

// scheduleBatchOperationsAsDeployer schedules multiple operations at once through MCMS
// This properly batches all operations in a single execute call
func scheduleBatchOperationsAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, mcmsAccount aptos.AccountAddress, deployerAddress string,
	deployerPublicKeyHex string, ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, nonce uint64, proof [][32]byte) string {

	// Serialize all operations into a single schedule_batch call
	serializedData, err := serializeScheduleBatchParams(ops, predecessor, salt, delay)
	require.NoError(t, err)

	// Create a single Op struct for the execute call
	op := Op{
		Role:         role,
		ChainID:      chainId,
		MultiSig:     mcmsAccount,
		Nonce:        nonce,
		To:           mcmsAccount,
		ModuleName:   "mcms",
		FunctionName: "timelock_schedule_batch",
		Data:         serializedData,
	}

	// Log the operation details
	logger.Debugw("Batch operation details",
		"role", op.Role,
		"chainId", op.ChainID,
		"multisig", op.MultiSig.String(),
		"nonce", op.Nonce,
		"to", op.To.String(),
		"moduleName", op.ModuleName,
		"functionName", op.FunctionName,
		"dataLength", len(op.Data),
		"numOperations", len(ops),
	)

	// Compute and log the leaf hash
	leafHash := hashOp(&op)
	logger.Debugw("Leaf hash", "value", hex.EncodeToString(leafHash[:]))

	// Verify that the provided proof matches our calculated leaf hash
	computedHash := leafHash
	for i, p := range proof {
		computedHash = hashPair(computedHash, p)
		logger.Debugw("Intermediate hash", "step", i, "value", hex.EncodeToString(computedHash[:]))
	}

	// Call execute once with all operations
	txId := uuid.New().String()
	err = txm.Enqueue(
		txId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAccount.String()+"::mcms::execute",
		[]string{},
		[]string{
			"u8",                  // role
			"u256",                // chainId
			"address",             // multisig
			"u64",                 // nonce
			"address",             // to
			"0x1::string::String", // moduleName
			"0x1::string::String", // function
			"vector<u8>",          // data
			"vector<vector<u8>>",  // proof
		},
		[]any{
			role,
			chainId,
			mcmsAccount,
			nonce,
			op.To,
			op.ModuleName,
			op.FunctionName,
			op.Data,
			proof[:],
		},
		true,
	)
	require.NoError(t, err)

	waitForTxmId(t, txm, txId, time.Second*30)

	return txId
}

func getFunctionOneParamBytes(t *testing.T, arg1 string, arg2 []byte) []byte {
	// function_one(arg1: String, arg2: vector<u8>)
	functionOneParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteString(arg1)
		ser.WriteBytes(arg2)
	})
	require.NoError(t, err)
	return functionOneParamBytes
}

func getFunctionTwoParamBytes(t *testing.T, arg1 []byte, arg2 *big.Int) []byte {
	// function_two(arg1: address, arg2: u128)
	functionTwoParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.FixedBytes(arg1)
		ser.U128(*arg2)
	})
	require.NoError(t, err)
	return functionTwoParamBytes
}

func HashOperationBatch(targets []aptos.AccountAddress, moduleNames, functionNames []string, datas [][]byte, predecessor, salt []byte) (common.Hash, error) {
	ser := bcs.Serializer{}
	//nolint:gosec
	ser.Uleb128(uint32(len(targets)))
	for i, target := range targets {
		moduleName := moduleNames[i]
		functionName := functionNames[i]
		data := datas[i]

		ser.Struct(&target)
		ser.WriteString(moduleName)
		ser.WriteString(functionName)
		ser.WriteBytes(data)
	}
	ser.FixedBytes(predecessor)
	ser.FixedBytes(salt)

	if err := ser.Error(); err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(ser.ToBytes()), nil
}
