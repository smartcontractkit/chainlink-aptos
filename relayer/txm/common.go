package txm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/aptos-labs/aptos-go-sdk/bcs"

	"github.com/ethereum/go-ethereum/common"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

// Constants
const TEST_DELAY = uint64(1)
const BYPASSER_ROLE = 0
const CANCELLOR_ROLE = 1
const PROPOSER_ROLE = 2

// Types
type Signer struct {
	Address    []byte
	PrivateKey *ecdsa.PrivateKey
}

type RootMetadata struct {
	Role                 uint8
	ChainID              *big.Int
	MultiSig             aptos.AccountAddress
	PreOpCount           uint64
	PostOpCount          uint64
	OverridePreviousRoot bool
}

type Op struct {
	Role         uint8
	ChainID      *big.Int
	MultiSig     aptos.AccountAddress
	Nonce        uint64
	To           aptos.AccountAddress
	ModuleName   string
	FunctionName string
	Data         []byte
}

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

type MerkleTree [][32]byte

// Utility Functions
func GetSampleTxMetadata() *commontypes.TxMeta {
	workflowID := "sample-workflow-id"
	return &commontypes.TxMeta{
		WorkflowExecutionID: &workflowID,
		GasLimit:            big.NewInt(210000),
	}
}

func WaitForTxmId(t *testing.T, txm *AptosTxm, txId string, duration time.Duration) {
	stopTime := time.Now().Add(duration)
	for time.Now().Before(stopTime) {
		time.Sleep(time.Second * 1)
		status, err := txm.GetStatus(txId)
		require.NoError(t, err)
		if status == commontypes.Finalized {
			return
		}
	}
	t.Fatalf("Failed to wait for txmId %s", txId)
}

func GenerateSigners(t *testing.T, count int) []Signer {
	signers := make([]Signer, count)
	for i := 0; i < count; i++ {
		privateKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		signers[i] = Signer{
			Address:    crypto.PubkeyToAddress(privateKey.PublicKey).Bytes(),
			PrivateKey: privateKey,
		}
	}

	// Sort signers by address as required by the module
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i].Address, signers[j].Address) < 0
	})

	return signers
}

func CreateViewPayload(mcmsAddress string, module string, function string, argTypes []aptos.TypeTag, args [][]byte) *aptos.ViewPayload {
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

func SerializeSetConfig(role uint8, config SignerConfig) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// role: u8
		ser.U8(role)

		// signer_addresses: vector<vector<u8>>
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

func WriteAddress(ser *bcs.Serializer, addr aptos.AccountAddress) {
	ser.FixedBytes(addr[:])
}

func SerializeScheduleBatchParams(ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// Serialize targets vector
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			WriteAddress(ser, op.Target)
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

// SerializeStageCodeChunkParams serializes parameters for stage_code_chunk (3 parameters)
func SerializeStageCodeChunkParams(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteBytes(metadataChunk)

		// Serialize indices
		ser.Uleb128(uint32(len(codeIndices)))
		for _, idx := range codeIndices {
			ser.U16(idx)
		}

		// Serialize chunks
		ser.Uleb128(uint32(len(codeChunks)))
		for _, chunk := range codeChunks {
			ser.WriteBytes(chunk)
		}
	})
}

// SerializeStageCodeChunkAndPublishParams serializes parameters for stage_code_chunk_and_publish_to_object (4 parameters)
func SerializeStageCodeChunkAndPublishParams(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, newOwnerSeed []byte) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteBytes(metadataChunk)

		// Serialize indices
		ser.Uleb128(uint32(len(codeIndices)))
		for _, idx := range codeIndices {
			ser.U16(idx)
		}

		// Serialize chunks
		ser.Uleb128(uint32(len(codeChunks)))
		for _, chunk := range codeChunks {
			ser.WriteBytes(chunk)
		}

		ser.WriteBytes(newOwnerSeed)
	})
}

func TimelockOpsToOp(
	tlOps []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, mcmsAccount aptos.AccountAddress, getNextNonce func() uint64) Op {

	// Serialize all operations at once for schedule_batch
	serializedData, err := SerializeScheduleBatchParams(tlOps, predecessor, salt, delay)
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

func HashPair(left, right [32]byte) [32]byte {
	if bytes.Compare(left[:], right[:]) < 0 {
		return crypto.Keccak256Hash(left[:], right[:])
	}
	return crypto.Keccak256Hash(right[:], left[:])
}

// MerkleTree methods
func (mt MerkleTree) GetRoot() [32]byte {
	return mt[len(mt)-1]
}

func (mt MerkleTree) GetProof(index int) [][32]byte {
	proof := [][32]byte{}

	for index < len(mt)-1 {
		siblingIndex := index ^ 1
		proof = append(proof, mt[siblingIndex])
		index = (len(mt) + 1 + index) / 2
	}

	return proof
}

func (mt MerkleTree) VerifyProof(proof [][32]byte, leaf [32]byte) bool {
	computedHash := leaf
	for _, p := range proof {
		computedHash = HashPair(computedHash, p)
	}
	return bytes.Compare(computedHash[:], mt[len(mt)-1][:]) == 0
}

func NewMerkleTree(leaves [][32]byte) (MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("empty leaf set")
	}

	// Calculate the next power of 2
	leafCount := len(leaves)
	treeSize := 1
	for treeSize < leafCount {
		treeSize *= 2
	}

	// Create a new slice with the correct size
	paddedLeaves := make([][32]byte, treeSize)
	copy(paddedLeaves, leaves)

	// Fill the rest with zero leaves
	zeroLeaf := [32]byte{}
	for i := leafCount; i < treeSize; i++ {
		paddedLeaves[i] = zeroLeaf
	}

	tree := make(MerkleTree, treeSize)
	copy(tree, paddedLeaves)

	index := 0
	for levelSize := treeSize; levelSize > 1; levelSize /= 2 {
		for i := index; i < index+levelSize; i += 2 {
			tree = append(tree, HashPair(tree[i], tree[i+1]))
		}
		index += levelSize
	}

	return tree, nil
}

func HashRootMetadata(metadata RootMetadata) (common.Hash, error) {
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA_APTOS"))
	ser := bcs.Serializer{}
	ser.FixedBytes(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA)
	ser.U8(metadata.Role)
	ser.U256(*metadata.ChainID)
	ser.Struct(&metadata.MultiSig)
	ser.U64(metadata.PreOpCount)
	ser.U64(metadata.PostOpCount)
	ser.Bool(metadata.OverridePreviousRoot)

	if err := ser.Error(); err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(ser.ToBytes()), nil
}

func HashOp(op *Op) (common.Hash, error) {
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS"))
	ser := bcs.Serializer{}
	ser.FixedBytes(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP)
	ser.U8(op.Role)
	ser.U256(*op.ChainID)
	ser.Struct(&op.MultiSig)
	ser.U64(op.Nonce)
	ser.Struct(&op.To)
	ser.WriteString(op.ModuleName)
	ser.WriteString(op.FunctionName)
	ser.WriteBytes(op.Data)

	if err := ser.Error(); err != nil {
		return common.Hash{}, err
	}

	return crypto.Keccak256Hash(ser.ToBytes()), nil
}

func CalculateSignedHash(rootHash [32]byte, validUntil uint64) [32]byte {
	// Equivalent to Solidity's abi.encode(bytes32, uint64)
	data := make([]byte, 64)
	copy(data[:32], rootHash[:])
	binary.BigEndian.PutUint64(data[56:], validUntil)

	// Keccak256 hash of the ABI encoded parameters
	hashedEncodedParams := crypto.Keccak256(data)

	// Prepare the Ethereum signed message
	prefix := []byte("\x19Ethereum Signed Message:\n32")
	ethMsg := append(prefix, hashedEncodedParams...)

	// Final Keccak256 hash
	return crypto.Keccak256Hash(ethMsg)
}

func GenerateSignatures(t *testing.T, signers []Signer, signedHash [32]byte) [][]byte {
	signatures := make([][]byte, len(signers))
	for i, signer := range signers {
		signature, err := crypto.Sign(signedHash[:], signer.PrivateKey)
		require.NoError(t, err)

		// Adjust the v value, we need to readd 27.
		// ref: https://github.com/ethereum/go-ethereum/blob/b590cae89232299d54aac8aada88c66d00c5b34c/crypto/signature_nocgo.go#L90
		v := signature[crypto.RecoveryIDOffset]
		require.True(t, v >= 0 && v <= 3, "v should be between 0 and 3")
		signature[crypto.RecoveryIDOffset] += 27

		signatures[i] = signature
	}
	return signatures
}

func GenerateMerkleTree(ops []Op, rootMetadata RootMetadata) (MerkleTree, error) {
	leaves := make([][32]byte, len(ops)+1)
	rootHash, err := HashRootMetadata(rootMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to hash root metadata: %w", err)
	}
	leaves[0] = rootHash
	for i, op := range ops {
		hashOp, err := HashOp(&op)
		if err != nil {
			return nil, fmt.Errorf("failed to hash operation: %w", err)
		}
		leaves[i+1] = hashOp
	}
	return NewMerkleTree(leaves)
}

func ExecuteBatchOperations(
	t *testing.T, txm *AptosTxm, mcmsAddress string, deployerAddress string, deployerPublicKeyHex string,
	ops []TimelockOperation, predecessor []byte, salt []byte, simulateTx bool,
) string {

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
		GetSampleTxMetadata(),
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
		simulateTx,
	)
	require.NoError(t, err)
	return txId
}

func GetFunctionOneParamBytes(t *testing.T, arg1 string, arg2 []byte) []byte {
	// function_one(arg1: String, arg2: vector<u8>)
	functionOneParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteString(arg1)
		ser.WriteBytes(arg2)
	})
	require.NoError(t, err)
	return functionOneParamBytes
}

func GetFunctionTwoParamBytes(t *testing.T, arg1 []byte, arg2 *big.Int) []byte {
	// function_two(arg1: address, arg2: u128)
	functionTwoParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.FixedBytes(arg1)
		ser.U128(*arg2)
	})
	require.NoError(t, err)
	return functionTwoParamBytes
}

func EnqueueSetRoot(
	t *testing.T, logger logger.Logger, merkleTree MerkleTree, txm *AptosTxm, rootMetadata RootMetadata,
	signers []Signer, deployerAddress string, deployerPublicKeyHex string, mcmsAddress string,
) string {
	rootHash := merkleTree.GetRoot()

	// Set validUntil to be the current UTC timestamp + 1 day
	validUntil := uint64(time.Now().UTC().Add(1 * 24 * time.Hour).Unix())

	signedHash := CalculateSignedHash(rootHash, validUntil)
	signatures := GenerateSignatures(t, signers, signedHash)

	// The first leaf is the metadata
	metadataProof := merkleTree.GetProof(0)
	hashedRootMetadata, err := HashRootMetadata(rootMetadata)
	require.NoError(t, err)

	require.True(t, merkleTree.VerifyProof(metadataProof, hashedRootMetadata))

	// Log all values needed for Move e2e test
	logger.Debugw("============= BEGIN VALUES FOR MOVE E2E TEST =============")
	logger.Debugw("Root Hash", "value", hex.EncodeToString(rootHash[:]))
	logger.Debugw("Valid Until", "value", validUntil)
	logger.Debugw("Signed Hash", "value", hex.EncodeToString(signedHash[:]))

	signaturesHex := make([]string, len(signatures))
	for i, sig := range signatures {
		signaturesHex[i] = hex.EncodeToString(sig)
	}
	logger.Debugw("Signatures", "values", signaturesHex)

	signerAddressesHex := make([]string, len(signers))
	for i, signer := range signers {
		signerAddressesHex[i] = hex.EncodeToString(signer.Address)
	}
	logger.Debugw("Signer Addresses", "values", signerAddressesHex)

	metadataProofHex := make([]string, len(metadataProof))
	for i, p := range metadataProof {
		metadataProofHex[i] = hex.EncodeToString(p[:])
	}
	logger.Debugw("Metadata Proof", "values", metadataProofHex)

	logger.Debugw("============= END VALUES FOR MOVE E2E TEST =============")

	setRootId := uuid.New().String()

	err = txm.Enqueue(
		setRootId,
		GetSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAddress+"::mcms::set_root",
		[]string{},
		[]string{
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
		},
		[]any{
			rootMetadata.Role,
			rootHash,
			validUntil,
			rootMetadata.ChainID,
			rootMetadata.MultiSig,
			rootMetadata.PreOpCount,
			rootMetadata.PostOpCount,
			rootMetadata.OverridePreviousRoot,
			metadataProof,
			signatures,
		},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	return setRootId
}

func ScheduleSingleOperationAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, mcmsAccount aptos.AccountAddress, deployerAddress string,
	deployerPublicKeyHex string, ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, nonce uint64, proof [][32]byte, simulateTx bool,
) string {
	if len(ops) != 1 {
		panic("ScheduleSingleOperationAsDeployer expects exactly one operation")
	}

	// Create the Op struct to compute its hash - must match EXACTLY what was used in the Merkle tree
	serializedData, err := SerializeScheduleBatchParams([]TimelockOperation{ops[0]}, predecessor, salt, delay)
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
	leafHash, err := HashOp(&op)
	require.NoError(t, err)
	logger.Debugw("Leaf hash", "value", hex.EncodeToString(leafHash[:]))

	// Log each proof element
	for i, p := range proof {
		logger.Debugw("Proof element", "index", i, "value", hex.EncodeToString(p[:]))
	}

	// Verify and log each step of the proof computation
	computedHash := leafHash
	for i, p := range proof {
		computedHash = HashPair(computedHash, p)
		logger.Debugw("Intermediate hash", "step", i, "value", hex.EncodeToString(computedHash[:]))
	}

	txId := uuid.New().String()
	err = txm.Enqueue(
		txId,
		GetSampleTxMetadata(),
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
		simulateTx,
	)
	require.NoError(t, err)

	WaitForTxmId(t, txm, txId, time.Second*30)

	return txId
}

func ScheduleBatchOperationsAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, mcmsAccount aptos.AccountAddress, deployerAddress string,
	deployerPublicKeyHex string, ops []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, nonce uint64, proof [][32]byte, simulateTx bool,
) string {

	// Serialize all operations into a single schedule_batch call
	serializedData, err := SerializeScheduleBatchParams(ops, predecessor, salt, delay)
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
	leafHash, err := HashOp(&op)
	require.NoError(t, err)
	logger.Debugw("Leaf hash", "value", hex.EncodeToString(leafHash[:]))

	// Verify that the provided proof matches our calculated leaf hash
	computedHash := leafHash
	for i, p := range proof {
		computedHash = HashPair(computedHash, p)
		logger.Debugw("Intermediate hash", "step", i, "value", hex.EncodeToString(computedHash[:]))
	}

	// Call execute once with all operations
	txId := uuid.New().String()
	err = txm.Enqueue(
		txId,
		GetSampleTxMetadata(),
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
		simulateTx,
	)
	require.NoError(t, err)

	WaitForTxmId(t, txm, txId, time.Second*30)

	return txId
}

func HashOperationBatch(targets []aptos.AccountAddress, moduleNames, functionNames []string, datas [][]byte, predecessor, salt []byte) (common.Hash, error) {
	// Verify all arrays have the same length
	if len(targets) != len(moduleNames) || len(targets) != len(functionNames) || len(targets) != len(datas) {
		return common.Hash{}, fmt.Errorf("mismatched array lengths: targets=%d, moduleNames=%d, functionNames=%d, datas=%d",
			len(targets), len(moduleNames), len(functionNames), len(datas))
	}

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

// Setup initial config for a role
func SetupInitialConfigAsDeployer(
	t *testing.T, logger logger.Logger, txm *AptosTxm, role uint8, signers []Signer, deployerAddress string, deployerPublicKeyHex string,
	clearRoot bool, mcmsAddress string, simulateTx bool,
) {
	NUM_GROUPS := 32
	signerAddresses := [][]byte{}
	signerGroups := []uint8{}
	groupQuorums := make([]uint8, NUM_GROUPS)
	groupParents := make([]uint8, NUM_GROUPS)

	// Addresses are already sorted
	for _, signer := range signers {
		signerAddresses = append(signerAddresses, signer.Address)
		signerGroups = append(signerGroups, 0)
	}
	groupQuorums[0] = 2

	logger.Debugw("deployerAddress", "deployerAddress", deployerAddress)
	logger.Debugw("deployerPublicKeyHex", "deployerPublicKeyHex", deployerPublicKeyHex)

	setConfigId := uuid.New().String()
	err := txm.Enqueue(
		setConfigId,
		GetSampleTxMetadata(),
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
		simulateTx,
	)
	require.NoError(t, err)

	logger.Infow("waiting for txmId setConfigId to be created...", "setConfigId", setConfigId)
	WaitForTxmId(t, txm, setConfigId, time.Second*30)
}

// Transfer ownership of the mcms account
func TransferOwnership(t *testing.T, txm *AptosTxm, deployerAddress, deployerPublicKeyHex string, mcmsAddress string, simulateTx bool) {
	transferOwnershipId := uuid.New().String()
	err := txm.Enqueue(
		transferOwnershipId,
		GetSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		mcmsAddress+"::mcms_account::transfer_ownership_to_self",
		[]string{},
		[]string{},
		[]any{},
		simulateTx,
	)
	require.NoError(t, err)
	WaitForTxmId(t, txm, transferOwnershipId, time.Second*30)
}

// Get the multisig account for a role
func GetMultisigForRole(t *testing.T, mcmsAddress string, client *aptos.NodeClient, role uint8) aptos.AccountAddress {
	paramValues := [][]byte{}
	typeTag, err := CreateTypeTag("u8")
	require.NoError(t, err)
	bcsValue, err := CreateBcsValue(typeTag, role)
	require.NoError(t, err)
	paramValues = append(paramValues, bcsValue)

	viewPayload := CreateViewPayload(mcmsAddress, "mcms", "multisig_object", []aptos.TypeTag{}, paramValues)
	data, err := client.View(viewPayload)
	require.NoError(t, err)

	addr, err := UnwrapObject(data)
	require.NoError(t, err)
	return *addr
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

func TimelockOpToMultipleOps(tlOps []TimelockOperation, predecessor []byte, salt []byte, delay uint64,
	role uint8, chainId *big.Int, mcmsAccount aptos.AccountAddress, getNextNonce func() uint64) []Op {
	ops := make([]Op, len(tlOps))

	for i, tlOp := range tlOps {
		// For each operation, serialize its parameters individually
		serializedData, err := SerializeScheduleBatchParams([]TimelockOperation{tlOp}, predecessor, salt, delay)
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
