package txm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// CurseMCMS uses the same domain separators as the full MCMS
// These are keccak256 hashes of the domain separator strings
var (
	// keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA_APTOS")
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA = crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA_APTOS"))
	// keccak256("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS")
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP = crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS"))
)

// CurseMCMS RootMetadata - same as full MCMS
type CurseMCMSRootMetadata struct {
	Role                 uint8
	ChainID              *big.Int
	MultiSig             aptos.AccountAddress
	PreOpCount           uint64
	PostOpCount          uint64
	OverridePreviousRoot bool
}

// CurseMCMS Op - same as full MCMS
type CurseMCMSOp struct {
	Role         uint8
	ChainID      *big.Int
	MultiSig     aptos.AccountAddress
	Nonce        uint64
	To           aptos.AccountAddress
	ModuleName   string
	FunctionName string
	Data         []byte
}

// HashCurseMCMSRootMetadata computes the hash of CurseMCMS root metadata
func HashCurseMCMSRootMetadata(metadata CurseMCMSRootMetadata) ([32]byte, error) {
	ser := bcs.Serializer{}
	ser.FixedBytes(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA)
	ser.U8(metadata.Role)
	ser.U256(*metadata.ChainID)
	ser.Struct(&metadata.MultiSig)
	ser.U64(metadata.PreOpCount)
	ser.U64(metadata.PostOpCount)
	ser.Bool(metadata.OverridePreviousRoot)

	if err := ser.Error(); err != nil {
		return [32]byte{}, err
	}

	return crypto.Keccak256Hash(ser.ToBytes()), nil
}

// HashCurseMCMSOp computes the hash of a CurseMCMS operation
func HashCurseMCMSOp(op *CurseMCMSOp) ([32]byte, error) {
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
		return [32]byte{}, err
	}

	return crypto.Keccak256Hash(ser.ToBytes()), nil
}

// GenerateCurseMCMSMerkleTree creates a merkle tree for CurseMCMS operations
func GenerateCurseMCMSMerkleTree(ops []CurseMCMSOp, metadata CurseMCMSRootMetadata) (MerkleTree, error) {
	leaves := make([][32]byte, len(ops)+1)
	rootHash, err := HashCurseMCMSRootMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to hash root metadata: %w", err)
	}
	leaves[0] = rootHash
	for i, op := range ops {
		hashOp, err := HashCurseMCMSOp(&op)
		if err != nil {
			return nil, fmt.Errorf("failed to hash operation: %w", err)
		}
		leaves[i+1] = hashOp
	}
	return NewMerkleTree(leaves)
}

// SerializeCurseData serializes a single curse subject for the data field (vector<u8>)
func SerializeCurseData(subject []byte) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteBytes(subject)
	})
}

// SerializeCurseMultipleData serializes multiple curse subjects for the data field (vector<vector<u8>>)
func SerializeCurseMultipleData(subjects [][]byte) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.Uleb128(uint32(len(subjects)))
		for _, subject := range subjects {
			ser.WriteBytes(subject)
		}
	})
}

// CurseMCMSTimelockOperation represents a single operation in timelock_bypasser_execute_batch
type CurseMCMSTimelockOperation struct {
	Target       aptos.AccountAddress
	ModuleName   string
	FunctionName string
	Data         []byte
}

// SerializeBypasserExecuteBatch serializes the data for timelock_bypasher_execute_batch
// Follows the MCMS pattern: targets, module_names, function_names, datas as separate vectors
func SerializeBypasserExecuteBatch(ops []CurseMCMSTimelockOperation) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// targets: vector<address>
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			WriteAddress(ser, op.Target)
		}

		// module_names: vector<String>
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteString(op.ModuleName)
		}

		// function_names: vector<String>
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteString(op.FunctionName)
		}

		// datas: vector<vector<u8>>
		ser.Uleb128(uint32(len(ops)))
		for _, op := range ops {
			ser.WriteBytes(op.Data)
		}
	})
}

// GenerateDeterministicSigners creates signers with fixed private keys for reproducible tests
func GenerateDeterministicSigners(t *testing.T) []Signer {
	// Fixed private keys for deterministic test data
	// These are test keys ONLY - never use in production
	privateKeyHexes := []string{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"0000000000000000000000000000000000000000000000000000000000000003",
	}

	signers := make([]Signer, len(privateKeyHexes))
	for i, hexKey := range privateKeyHexes {
		keyBytes, err := hex.DecodeString(hexKey)
		require.NoError(t, err)
		privateKey, err := crypto.ToECDSA(keyBytes)
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

// TestGenerateCurseMCMSTestData generates test data for CurseMCMS Move tests
// Run with: go test -v -run TestGenerateCurseMCMSTestData ./relayer/txm/
func TestGenerateCurseMCMSTestData(t *testing.T) {
	// Use fixed chain ID (same as Move tests)
	chainID := big.NewInt(4)

	// Use BYPASSER_ROLE for testing (role 0)
	role := uint8(0)

	// Use a deterministic CurseMCMS address for testing
	// This should match the dev-address in Move.toml: 0xCCC
	curseMCMSAddr := aptos.AccountAddress{}
	err := curseMCMSAddr.ParseStringRelaxed("0x0000000000000000000000000000000000000000000000000000000000000CCC")
	require.NoError(t, err)

	// CCIP address for rmn_remote operations
	// This should match the dev-address in curse_mcms/Move.toml for ccip
	ccipAddr := aptos.AccountAddress{}
	err = ccipAddr.ParseStringRelaxed("0x30b33dec3fcac5ef3ea775128d88722b64ba59a4598277e537f284917403df29")
	require.NoError(t, err)

	// Use deterministic signers for reproducible test data
	signers := GenerateDeterministicSigners(t)

	// Test curse subject (GLOBAL_CURSE_SUBJECT from rmn_remote.move)
	globalCurseSubject := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	subject2 := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}

	// Create curse operation data (for rmn_remote::curse)
	curseData, err := SerializeCurseData(globalCurseSubject)
	require.NoError(t, err)

	// Create uncurse operation data (for rmn_remote::uncurse)
	uncurseData, err := SerializeCurseData(globalCurseSubject)
	require.NoError(t, err)

	// Create curse_multiple operation data (for rmn_remote::curse_multiple)
	curseMultipleData, err := SerializeCurseMultipleData([][]byte{globalCurseSubject, subject2})
	require.NoError(t, err)

	// Operation 1: timelock_bypasser_execute_batch with a single curse call (targets rmn_remote)
	op1Data, err := SerializeBypasserExecuteBatch([]CurseMCMSTimelockOperation{
		{
			Target:       ccipAddr,
			ModuleName:   "rmn_remote",
			FunctionName: "curse",
			Data:         curseData,
		},
	})
	require.NoError(t, err)

	// Operation 2: timelock_bypasser_execute_batch with a single uncurse call (targets rmn_remote)
	op2Data, err := SerializeBypasserExecuteBatch([]CurseMCMSTimelockOperation{
		{
			Target:       ccipAddr,
			ModuleName:   "rmn_remote",
			FunctionName: "uncurse",
			Data:         uncurseData,
		},
	})
	require.NoError(t, err)

	// Operation 3: timelock_bypasser_execute_batch with curse_multiple call (targets rmn_remote)
	op3Data, err := SerializeBypasserExecuteBatch([]CurseMCMSTimelockOperation{
		{
			Target:       ccipAddr,
			ModuleName:   "rmn_remote",
			FunctionName: "curse_multiple",
			Data:         curseMultipleData,
		},
	})
	require.NoError(t, err)

	// Create operations - all target curse_mcms module (timelock dispatch)
	ops := []CurseMCMSOp{
		{
			Role:         role,
			ChainID:      chainID,
			MultiSig:     curseMCMSAddr,
			Nonce:        0,
			To:           curseMCMSAddr, // Target is curse_mcms itself
			ModuleName:   "curse_mcms",  // Dispatches to curse_mcms module
			FunctionName: "timelock_bypasser_execute_batch",
			Data:         op1Data,
		},
		{
			Role:         role,
			ChainID:      chainID,
			MultiSig:     curseMCMSAddr,
			Nonce:        1,
			To:           curseMCMSAddr,
			ModuleName:   "curse_mcms",
			FunctionName: "timelock_bypasser_execute_batch",
			Data:         op2Data,
		},
		{
			Role:         role,
			ChainID:      chainID,
			MultiSig:     curseMCMSAddr,
			Nonce:        2,
			To:           curseMCMSAddr,
			ModuleName:   "curse_mcms",
			FunctionName: "timelock_bypasser_execute_batch",
			Data:         op3Data,
		},
	}

	// Create root metadata
	metadata := CurseMCMSRootMetadata{
		Role:                 role,
		ChainID:              chainID,
		MultiSig:             curseMCMSAddr,
		PreOpCount:           0,
		PostOpCount:          uint64(len(ops)),
		OverridePreviousRoot: false,
	}

	// Generate merkle tree
	merkleTree, err := GenerateCurseMCMSMerkleTree(ops, metadata)
	require.NoError(t, err)

	// Get root hash
	rootHash := merkleTree.GetRoot()

	// Use a fixed validUntil timestamp for deterministic tests
	// This should be far in the future for the Move tests to work
	validUntil := uint64(1893456000) // Jan 1, 2030

	// Calculate signed hash
	signedHash := CalculateSignedHash(rootHash, validUntil)

	// Generate signatures (only need 2 for quorum)
	signatures := GenerateSignatures(t, signers[:2], signedHash)

	// Get metadata proof
	metadataProof := merkleTree.GetProof(0)

	// Get operation proofs
	op1Proof := merkleTree.GetProof(1)
	op2Proof := merkleTree.GetProof(2)
	op3Proof := merkleTree.GetProof(3)

	// Print all values for Move tests
	fmt.Println("============= BEGIN CURSE_MCMS MOVE TEST CONSTANTS =============")
	fmt.Println()

	fmt.Println("// Domain Separators (same as full MCMS)")
	fmt.Printf("const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA: vector<u8> = x\"%s\";\n", hex.EncodeToString(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA))
	fmt.Printf("const MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: vector<u8> = x\"%s\";\n", hex.EncodeToString(MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP))
	fmt.Println()

	fmt.Println("// Test Configuration")
	fmt.Printf("const CHAIN_ID: u256 = %d;\n", chainID)
	fmt.Printf("const VALID_UNTIL: u64 = %d;\n", validUntil)
	fmt.Printf("const TEST_ROLE: u8 = %d;\n", role)
	fmt.Println()

	fmt.Println("// Contract Addresses")
	fmt.Printf("// CURSE_MCMS_ADDR: @0x%s\n", hex.EncodeToString(curseMCMSAddr[:]))
	fmt.Printf("// CCIP_ADDR: @0x%s\n", hex.EncodeToString(ccipAddr[:]))
	fmt.Println()

	fmt.Println("// Signer Addresses (sorted, 20 bytes each)")
	for i, signer := range signers {
		fmt.Printf("const SIGNER_%d: vector<u8> = x\"%s\";\n", i+1, hex.EncodeToString(signer.Address))
	}
	fmt.Println()

	fmt.Println("// Root and Metadata")
	fmt.Printf("const ROOT: vector<u8> = x\"%s\";\n", hex.EncodeToString(rootHash[:]))
	fmt.Println()

	fmt.Println("// Metadata Proof")
	fmt.Print("const METADATA_PROOF: vector<vector<u8>> = vector[\n")
	for i, p := range metadataProof {
		if i < len(metadataProof)-1 {
			fmt.Printf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			fmt.Printf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	fmt.Println("];")
	fmt.Println()

	fmt.Println("// Signatures (2-of-3 quorum)")
	fmt.Print("const SIGNATURES: vector<vector<u8>> = vector[\n")
	for i, sig := range signatures {
		if i < len(signatures)-1 {
			fmt.Printf("    x\"%s\",\n", hex.EncodeToString(sig))
		} else {
			fmt.Printf("    x\"%s\"\n", hex.EncodeToString(sig))
		}
	}
	fmt.Println("];")
	fmt.Println()

	fmt.Println("// All operations target curse_mcms module and timelock_bypasser_execute_batch function")
	fmt.Printf("const TARGET_MODULE: vector<u8> = b\"%s\";\n", ops[0].ModuleName)
	fmt.Printf("const TARGET_FUNCTION: vector<u8> = b\"%s\";\n", ops[0].FunctionName)
	fmt.Println()

	fmt.Println("// Operation 1: curse via timelock_bypasser_execute_batch")
	fmt.Printf("const OP1_NONCE: u64 = %d;\n", ops[0].Nonce)
	fmt.Printf("const OP1_DATA: vector<u8> = x\"%s\";\n", hex.EncodeToString(ops[0].Data))
	fmt.Print("const OP1_PROOF: vector<vector<u8>> = vector[\n")
	for i, p := range op1Proof {
		if i < len(op1Proof)-1 {
			fmt.Printf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			fmt.Printf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	fmt.Println("];")
	fmt.Println()

	fmt.Println("// Operation 2: uncurse via timelock_bypasser_execute_batch")
	fmt.Printf("const OP2_NONCE: u64 = %d;\n", ops[1].Nonce)
	fmt.Printf("const OP2_DATA: vector<u8> = x\"%s\";\n", hex.EncodeToString(ops[1].Data))
	fmt.Print("const OP2_PROOF: vector<vector<u8>> = vector[\n")
	for i, p := range op2Proof {
		if i < len(op2Proof)-1 {
			fmt.Printf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			fmt.Printf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	fmt.Println("];")
	fmt.Println()

	fmt.Println("// Operation 3: curse_multiple via timelock_bypasser_execute_batch")
	fmt.Printf("const OP3_NONCE: u64 = %d;\n", ops[2].Nonce)
	fmt.Printf("const OP3_DATA: vector<u8> = x\"%s\";\n", hex.EncodeToString(ops[2].Data))
	fmt.Print("const OP3_PROOF: vector<vector<u8>> = vector[\n")
	for i, p := range op3Proof {
		if i < len(op3Proof)-1 {
			fmt.Printf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			fmt.Printf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	fmt.Println("];")
	fmt.Println()

	fmt.Println("// Curse Subjects")
	fmt.Printf("const GLOBAL_CURSE_SUBJECT: vector<u8> = x\"%s\";\n", hex.EncodeToString(globalCurseSubject))
	fmt.Printf("const SUBJECT_2: vector<u8> = x\"%s\";\n", hex.EncodeToString(subject2))
	fmt.Println()

	fmt.Println("============= END CURSE_MCMS MOVE TEST CONSTANTS =============")

	// Verify the merkle tree
	hashedMetadata, err := HashCurseMCMSRootMetadata(metadata)
	require.NoError(t, err)
	require.True(t, merkleTree.VerifyProof(metadataProof, hashedMetadata), "Metadata proof verification failed")

	for i, op := range ops {
		hashedOp, err := HashCurseMCMSOp(&op)
		require.NoError(t, err)
		proof := merkleTree.GetProof(i + 1)
		require.True(t, merkleTree.VerifyProof(proof, hashedOp), "Op %d proof verification failed", i)
	}
}

// TestCurseMCMSDomainSeparators prints the domain separators for verification
func TestCurseMCMSDomainSeparators(t *testing.T) {
	metadataSep := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA_APTOS"))
	opSep := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP_APTOS"))

	fmt.Printf("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA: %s\n", hex.EncodeToString(metadataSep))
	fmt.Printf("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP: %s\n", hex.EncodeToString(opSep))
}
