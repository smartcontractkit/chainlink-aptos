package txm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

// Regenerate mcms_test.move e2e constants
// Run: go test ./relayer/txm -run TestRegenMcmsTestConstants -v
func TestRegenMcmsTestConstants(t *testing.T) {
	mcmsAccount := aptos.AccountAddress{}
	require.NoError(t, mcmsAccount.ParseStringRelaxed("0xa969156fce9a4f08bcdc07b90f338efc630bff8dfa8340500cb6414aca762a4e"))

	chainID := big.NewInt(4)
	role := uint8(2)
	predecessor := make([]byte, 32)
	salt := make([]byte, 32)
	delay := uint64(1)

	op1Data, err := SerializeScheduleBatchParams(
		[]TimelockOperation{{
			Target: mcmsAccount, ModuleName: "mcms_account",
			FunctionName: "accept_ownership", Data: []byte{},
		}},
		predecessor, salt, delay,
	)
	require.NoError(t, err)

	op1 := Op{
		Role: role, ChainID: chainID, MultiSig: mcmsAccount, Nonce: 0,
		To: mcmsAccount, ModuleName: "mcms", FunctionName: "timelock_schedule_batch",
		Data: op1Data,
	}
	op1Leaf, err := HashOp(&op1)
	require.NoError(t, err)

	// Unchanged op leaves from mcms_test.move LEAVES (ops 2-4)
	op2, _ := hex.DecodeString("2feec0e3a232c5c847874246203e62c43db473fe85245095122e166be9114e13")
	op3, _ := hex.DecodeString("411a4726f8a920fc0a814bd9897a06f3dd0f1c799a047deaa6469f105f5a6705")
	op4, _ := hex.DecodeString("cb4dffef33843b197cd33346d3339d8432b14789504167c63fb9f74a73baaea5")
	metadataLeaf, _ := hex.DecodeString("a619565e90c1c564293b59b344ed0e12ed06eafb3c45b70baf6fdf299a046297")

	leaves := [][32]byte{
		bytes32(metadataLeaf), op1Leaf,
		bytes32(op2), bytes32(op3), bytes32(op4),
	}
	tree, err := NewMerkleTree(leaves)
	require.NoError(t, err)

	root := tree.GetRoot()
	validUntil := uint64(1744315405)
	signedHash := CalculateSignedHash(root, validUntil)

	// Use deterministic signers; addresses must match mcms_test PROPOSER_ADDR*
	signers := GenerateDeterministicSigners(t)
	signatures := GenerateSignatures(t, signers[:3], signedHash)

	op1Proof := tree.GetProof(1)
	metadataProof := tree.GetProof(0)

	var out string
	out += fmt.Sprintf("const ROOT: vector<u8> = x\"%s\";\n", hex.EncodeToString(root[:]))
	out += fmt.Sprintf("const OP1_DATA: vector<u8> = x\"%s\";\n", hex.EncodeToString(op1Data))
	out += "const OP1_PROOF: vector<vector<u8>> = vector[\n"
	for i, p := range op1Proof {
		if i < len(op1Proof)-1 {
			out += fmt.Sprintf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			out += fmt.Sprintf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	out += "];\n"
	out += "const METADATA_PROOF: vector<vector<u8>> = vector[\n"
	for i, p := range metadataProof {
		if i < len(metadataProof)-1 {
			out += fmt.Sprintf("    x\"%s\",\n", hex.EncodeToString(p[:]))
		} else {
			out += fmt.Sprintf("    x\"%s\"\n", hex.EncodeToString(p[:]))
		}
	}
	out += "];\n"
	out += "const SIGNATURES: vector<vector<u8>> = vector[\n"
	for i, sig := range signatures {
		if i < len(signatures)-1 {
			out += fmt.Sprintf("    x\"%s\",\n", hex.EncodeToString(sig))
		} else {
			out += fmt.Sprintf("    x\"%s\"\n", hex.EncodeToString(sig))
		}
	}
	out += "];\n"
	out += fmt.Sprintf("// LEAVES[1] op1: x\"%s\"\n", hex.EncodeToString(op1Leaf[:]))
	require.NoError(t, os.WriteFile("/tmp/mcms_test_constants.txt", []byte(out), 0o644))
}

func bytes32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], b)
	return out
}

// Ensure common.Hash compatible
var _ = common.Hash{}
