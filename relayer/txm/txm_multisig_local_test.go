//go:build integration

package txm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	aptoscrypto "github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/testutils"
)

type Account struct {
	privateKey     ed25519.PrivateKey
	publicKey      ed25519.PublicKey
	accountAddress aptos.AccountAddress
}

type Signer struct {
	// ethereum address
	address    []byte
	privateKey *ecdsa.PrivateKey
}

func TestMultisigLocal(t *testing.T) {
	logger := logger.Test(t)

	accounts := []Account{}
	keystore := testutils.NewTestKeystore(t)

	for i := 0; i < 5; i++ {
		var account Account
		if i == 0 {
			privateKey, publicKey, accountAddress := testutils.LoadAccountFromEnv(t, logger)
			if privateKey != nil {
				logger.Debugw("Loaded account", "publicKey", hex.EncodeToString([]byte(publicKey)), "accountAddress", accountAddress.String())
				account = Account{privateKey, publicKey, accountAddress}
			}
		}
		if account.privateKey == nil {
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			authKey := sha3.Sum256(append([]byte(publicKey), 0x00))
			accountAddress := aptos.AccountAddress(authKey)

			logger.Debugw("Created account", "publicKey", hex.EncodeToString([]byte(publicKey)), "accountAddress", accountAddress.String())
			account = Account{privateKey, publicKey, accountAddress}
		}
		accounts = append(accounts, account)
		keystore.AddKey(account.privateKey)
	}

	signers := []Signer{}
	for i := 0; i < 3; i++ {
		privateKey, err := crypto.GenerateKey()
		require.NoError(t, err)
		signer := Signer{
			address:    crypto.PubkeyToAddress(privateKey.PublicKey).Bytes(),
			privateKey: privateKey,
		}
		signers = append(signers, signer)
		logger.Debugw("Generated signer", "address", hex.EncodeToString(signer.address))
	}

	// Sort signers by address as required by the module
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i].address, signers[j].address) < 0
	})

	err := testutils.StartAptosNode()
	require.NoError(t, err)
	logger.Debugw("Started Aptos node")

	rpcUrl := "http://localhost:8080/v1"
	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	faucetUrl := "http://localhost:8081"
	for _, account := range accounts {
		err = testutils.FundWithFaucet(logger, client, account.accountAddress, faucetUrl)
		require.NoError(t, err)
	}

	runMultisigTest(t, logger, rpcUrl, keystore, accounts, signers)
}

func runMultisigTest(t *testing.T, logger logger.Logger, rpcURL string, keystore loop.Keystore, accounts []Account, signers []Signer) {
	deployer := accounts[0]
	deployerAddress := deployer.accountAddress.String()
	deployerPublicKeyHex := hex.EncodeToString([]byte(deployer.publicKey))

	mcmsUserDeployer := accounts[1]
	mcmsUserDeployerAddress := mcmsUserDeployer.accountAddress.String()
	mcmsUserDeployerPublicKeyHex := hex.EncodeToString([]byte(mcmsUserDeployer.publicKey))

	mcmsPackageMetadataBytes, mcmsModuleBytecodeBytes := compileMcmsContract(t, deployer.accountAddress)

	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)

	config := DefaultConfigSet
	getClient := func() (*aptos.NodeClient, error) { return client, nil }
	txm, err := New(logger, keystore, config, getClient)
	require.NoError(t, err)
	err = txm.Start(context.Background())
	require.NoError(t, err)

	// deploy mcms module
	err = txm.Enqueue(
		uuid.New().String(),
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{mcmsPackageMetadataBytes, mcmsModuleBytecodeBytes},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	// resource account address derived in init_module, creates the multisig account and is one of the signers
	mcmsStateAddress := deployer.accountAddress.NamedObjectAddress([]byte("CHAINLINK_MCMS_MULTISIG"))

	logger.Infow("published module", "deployerAddress", deployerAddress, "mcmsStateAddress", mcmsStateAddress.String())

	// Wait for the multisig to be initialized
	{
		pollEndTime := time.Now().Add(time.Second * 3)
		var resource map[string]any
		for time.Now().Before(pollEndTime) {
			resource, err = client.AccountResource(mcmsStateAddress, deployerAddress+"::mcms::State")
			if err != nil {
				time.Sleep(time.Second * 1)
				continue
			}
			logger.Debugw("Got resource", "resource", resource)
			break
		}
		require.NotNil(t, resource)
	}

	mcmsUserPackageMetadataBytes, mcmsUserModuleBytecodeBytes := compileMcmsUserContract(t, mcmsUserDeployer.accountAddress, deployer.accountAddress)

	// deploy and initialize mcms user module
	err = txm.Enqueue(
		uuid.New().String(),
		getSampleTxMetadata(),
		mcmsUserDeployerAddress,
		mcmsUserDeployerPublicKeyHex,
		"0x1::code::publish_package_txn",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{mcmsUserPackageMetadataBytes, [][]byte{mcmsUserModuleBytecodeBytes}},
		/* simulateTx= */ true,
	)
	require.NoError(t, err)

	// Wait for the user contract to be initialized
	{
		pollEndTime := time.Now().Add(time.Second * 30)
		var resource map[string]any
		for time.Now().Before(pollEndTime) {
			resource, err = client.AccountResource(mcmsUserDeployer.accountAddress, mcmsUserDeployerAddress+"::mcms_user::UserData")
			if err != nil {
				time.Sleep(time.Second * 1)
				continue
			}
			logger.Debugw("Got resource", "resource", resource)
			break
		}
		require.NotNil(t, resource)
	}

	// Call set_config to set signers
	{
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

		err := txm.Enqueue(
			uuid.New().String(),
			getSampleTxMetadata(),
			deployerAddress,
			deployerPublicKeyHex,
			deployerAddress+"::mcms::set_config",
			[]string{},
			[]string{"vector<vector<u8>>", "vector<u8>", "vector<u8>", "vector<u8>", "bool"},
			[]any{
				signerAddresses,
				signerGroups,
				groupQuorums,
				groupParents,
				false,
			},
			/* simulateTx= */ true,
		)
		require.NoError(t, err)

		// TODO: check for success
	}

	chainId, err := client.GetChainId()
	require.NoError(t, err)
	chainIdBig := new(big.Int).SetUint64(uint64(chainId))

	arg1 := "hello"
	arg2 := []byte{5, 4, 3, 2, 1}
	arg3 := mcmsUserDeployer.accountAddress[:]
	arg4 := big.NewInt(42)

	// function_one(arg1: String, arg2: vector<u8>)
	functionOneParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.WriteString(arg1)
		ser.WriteBytes(arg2)
	})
	require.NoError(t, err)

	// function_two(arg1: address, arg2: u128)
	functionTwoParamBytes, err := bcs.SerializeSingle(func(ser *bcs.Serializer) {
		ser.FixedBytes(arg3)
		ser.U128(*arg4)
	})
	require.NoError(t, err)

	ops := []Op{
		{
			ChainID:    chainIdBig,
			MultiSig:   deployer.accountAddress,
			Nonce:      0,
			To:         mcmsUserDeployer.accountAddress,
			ModuleName: "mcms_user",
			Function:   "function_one",
			Data:       functionOneParamBytes,
		},
		{
			ChainID:    chainIdBig,
			MultiSig:   deployer.accountAddress,
			Nonce:      1,
			To:         mcmsUserDeployer.accountAddress,
			ModuleName: "mcms_user",
			Function:   "function_two",
			Data:       functionTwoParamBytes,
		},
	}

	rootMetadata := RootMetadata{
		ChainID:              chainIdBig,
		MultiSig:             deployer.accountAddress,
		PreOpCount:           0,
		PostOpCount:          uint64(len(ops)),
		OverridePreviousRoot: false,
	}

	merkleTree, err := generateMerkleTree(ops, rootMetadata)
	require.NoError(t, err)

	// call set_root
	{
		rootHash := merkleTree.getRoot()

		// Set validUntil to be the current UTC timestamp + 1 week
		validUntil := uint64(time.Now().UTC().Add(7 * 24 * time.Hour).Unix())

		// Calculate signedHash
		signedHash := calculateSignedHash(rootHash, validUntil)

		// Generate signatures for each signer
		signatures := generateSignatures(t, signers, signedHash)

		// The first leaf is the metadata
		metadataProof := merkleTree.getProof(0)

		require.True(t, merkleTree.verifyProof(metadataProof, hashRootMetadata(rootMetadata)))

		err := txm.Enqueue(
			uuid.New().String(),
			getSampleTxMetadata(),
			deployerAddress,
			deployerPublicKeyHex,
			deployerAddress+"::mcms::set_root",
			[]string{},
			[]string{
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

		// TODO: check for success
	}

	for {
		queueLen, unconfirmedLen := txm.InflightCount()
		logger.Debugw("Inflight count", "queued", queueLen, "unconfirmed", unconfirmedLen)
		if queueLen == 0 && unconfirmedLen == 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	executeOp := func(index int) {
		logger.Debugw("Executing op", "index", index)

		// offset +1 to account for the root metadata
		proof := merkleTree.getProof(index + 1)
		op := &ops[index]
		require.True(t, merkleTree.verifyProof(proof, hashOp(op)))

		txId := uuid.New().String()

		err := txm.Enqueue(
			txId,
			getSampleTxMetadata(),
			deployerAddress,
			deployerPublicKeyHex,
			deployerAddress+"::mcms::execute",
			[]string{},
			[]string{
				"u256",
				"address",
				"u64",
				"address",
				"0x1::string::String",
				"0x1::string::String",
				"vector<u8>",
				"vector<vector<u8>>",
			},
			[]any{
				op.ChainID,
				op.MultiSig,
				op.Nonce,
				op.To,
				op.ModuleName,
				op.Function,
				op.Data,
				proof[:],
			},
			/* simulateTx= */ true,
		)
		require.NoError(t, err)

		waitForTxmId(t, txm, txId, time.Second*30)
	}

	logger.Infow("executing ops")
	executeOp(0)
	executeOp(1)

	// check that user contract state was updated
	{
		pollEndTime := time.Now().Add(time.Second * 30)
		var resource map[string]any

		for time.Now().Before(pollEndTime) {
			resource, err = client.AccountResource(mcmsUserDeployer.accountAddress, mcmsUserDeployerAddress+"::mcms_user::UserData")
			if err != nil {
				time.Sleep(time.Second * 1)
				continue
			}
			logger.Debugw("Got resource", "resource", resource)
			break
		}
		require.NotNil(t, resource)

		var result struct {
			Data struct {
				Invocations int
				A           string
				B           string
				C           string
				D           string
			}
		}
		err = mapstructure.Decode(resource, &result)
		require.NoError(t, err)

		require.Equal(t, result.Data.A, arg1)

		bBytes, err := hex.DecodeString(strings.TrimPrefix(result.Data.B, "0x"))
		require.NoError(t, err)
		require.Equal(t, bBytes, arg2)

		cBytes, err := hex.DecodeString(strings.TrimPrefix(result.Data.C, "0x"))
		require.NoError(t, err)
		require.Equal(t, cBytes, arg3)

		dInt, ok := new(big.Int).SetString(result.Data.D, 10)
		require.True(t, ok)
		require.Equal(t, dInt, arg4)
	}
}

func compileMcmsContract(t *testing.T, deployerAddress aptos.AccountAddress) ([]byte, [][]byte) {
	compileResult := testutils.CompileMovePackage(t, "mcms", map[string]aptos.AccountAddress{
		"mcms":       deployerAddress,
		"mcms_owner": deployerAddress,
	}, []string{
		"bcs_stream",
		"mcms_dispatcher",
		"mcms",
	})

	return compileResult.PackageMetadata, compileResult.BytecodeModules
}

func compileMcmsUserContract(t *testing.T, deployerAddress, mcmsAddress aptos.AccountAddress) ([]byte, []byte) {
	compileResult := testutils.CompileMovePackage(t, "mcms_test", map[string]aptos.AccountAddress{
		"mcms_test":  deployerAddress,
		"mcms":       mcmsAddress,
		"mcms_owner": mcmsAddress,
	}, nil)

	require.Equal(t, 1, len(compileResult.BytecodeModules))
	return compileResult.PackageMetadata, compileResult.BytecodeModules[0]
}

type RootMetadata struct {
	ChainID              *big.Int
	MultiSig             aptos.AccountAddress
	PreOpCount           uint64
	PostOpCount          uint64
	OverridePreviousRoot bool
}

type Op struct {
	ChainID    *big.Int
	MultiSig   aptos.AccountAddress
	Nonce      uint64
	To         aptos.AccountAddress
	ModuleName string
	Function   string
	Data       []byte
}

func generateMerkleTree(ops []Op, rootMetadata RootMetadata) (MerkleTree, error) {
	leaves := make([][32]byte, len(ops)+1)
	leaves[0] = hashRootMetadata(rootMetadata)
	for i, op := range ops {
		leaves[i+1] = hashOp(&op)
	}
	return newMerkleTree(leaves)
}

func hashRootMetadata(metadata RootMetadata) [32]byte {
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA"))

	packed := []byte{}
	packed = append(packed, MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_METADATA...)
	packed = append(packed, common.LeftPadBytes(metadata.ChainID.Bytes(), 32)...)
	packed = append(packed, metadata.MultiSig[:]...)
	packed = append(packed, common.LeftPadBytes(new(big.Int).SetUint64(metadata.PreOpCount).Bytes(), 32)...)
	packed = append(packed, common.LeftPadBytes(new(big.Int).SetUint64(metadata.PostOpCount).Bytes(), 32)...)
	if metadata.OverridePreviousRoot {
		packed = append(packed, common.LeftPadBytes([]byte{1}, 32)...)
	} else {
		packed = append(packed, common.LeftPadBytes([]byte{0}, 32)...)
	}

	hash := crypto.Keccak256(packed)
	var result [32]byte
	copy(result[:], hash)
	return result
}

func hashOp(op *Op) [32]byte {
	MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP := crypto.Keccak256([]byte("MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP"))

	packed := []byte{}
	packed = append(packed, MANY_CHAIN_MULTI_SIG_DOMAIN_SEPARATOR_OP...)
	packed = append(packed, common.LeftPadBytes(op.ChainID.Bytes(), 32)...)
	packed = append(packed, op.MultiSig[:]...)
	packed = append(packed, common.LeftPadBytes(new(big.Int).SetUint64(op.Nonce).Bytes(), 32)...)
	packed = append(packed, op.To[:]...)

	// Pack ModuleName with 64-byte left padding
	moduleNamePadded := common.LeftPadBytes([]byte(op.ModuleName), 64)
	packed = append(packed, moduleNamePadded...)

	// Pack Function with 64-byte left padding
	functionPadded := common.LeftPadBytes([]byte(op.Function), 64)
	packed = append(packed, functionPadded...)

	packed = append(packed, op.Data...)
	padAmount := 32 - (len(op.Data) % 32)
	for i := 0; i < padAmount; i++ {
		packed = append(packed, 0)
	}

	hash := crypto.Keccak256(packed)
	var result [32]byte
	copy(result[:], hash)
	return result
}

func hashPair(left, right [32]byte) [32]byte {
	if bytes.Compare(left[:], right[:]) < 0 {
		return crypto.Keccak256Hash(left[:], right[:])
	}
	return crypto.Keccak256Hash(right[:], left[:])
}

type MerkleTree [][32]byte

func (mt MerkleTree) getRoot() [32]byte {
	return mt[len(mt)-1]
}

func newMerkleTree(leaves [][32]byte) (MerkleTree, error) {
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
			tree = append(tree, hashPair(tree[i], tree[i+1]))
		}
		index += levelSize
	}

	return tree, nil
}

func (mt MerkleTree) getProof(index int) [][32]byte {
	proof := [][32]byte{}

	for index < len(mt)-1 {
		siblingIndex := index ^ 1
		proof = append(proof, mt[siblingIndex])
		index = (len(mt) + 1 + index) / 2
	}

	return proof
}

func (mt MerkleTree) verifyProof(proof [][32]byte, leaf [32]byte) bool {
	computedHash := leaf
	for _, p := range proof {
		computedHash = hashPair(computedHash, p)
	}
	return bytes.Compare(computedHash[:], mt[len(mt)-1][:]) == 0
}

func calculateSignedHash(rootHash [32]byte, validUntil uint64) [32]byte {
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

func generateSignatures(t *testing.T, signers []Signer, signedHash [32]byte) [][]byte {
	signatures := make([][]byte, len(signers))
	for i, signer := range signers {
		signature, err := crypto.Sign(signedHash[:], signer.privateKey)
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

func TestGetProof(t *testing.T) {
	leaves := [][32]byte{
		crypto.Keccak256Hash([]byte("leaf1")),
		crypto.Keccak256Hash([]byte("leaf2")),
		crypto.Keccak256Hash([]byte("leaf3")),
		crypto.Keccak256Hash([]byte("leaf4")),
	}

	fmt.Printf("Leaves: %v\n", leaves)

	tree, err := newMerkleTree(leaves)
	require.NoError(t, err)

	fmt.Printf("Tree: %v\n", tree)

	for i, leaf := range leaves {
		proof := tree.getProof(i)

		fmt.Printf("Proof for leaf %d: %v\n", i, proof)

		// Verify the proof
		isValid := tree.verifyProof(proof, leaf)
		require.True(t, isValid, "Proof should be valid for leaf %d", i)

		// Verify the proof manually
		computedHash := leaf
		for _, p := range proof {
			computedHash = hashPair(computedHash, p)
		}
		require.Equal(t, tree.getRoot(), computedHash, "Computed root should match tree root for leaf %d", i)
	}
}

func broadcastPayload(t *testing.T, client *aptos.NodeClient, keystore loop.Keystore, fromAddress aptos.AccountAddress, publicKey ed25519.PublicKey, payload aptos.TransactionPayload) *aptosapi.SubmitTransactionResponse {
	chainId, err := client.GetChainId()
	require.NoError(t, err)

	nodeInfo, err := client.Info()
	require.NoError(t, err)

	ledgerTimestamp := nodeInfo.LedgerTimestamp()
	require.NotEqual(t, ledgerTimestamp, 0)

	accountInfo, err := client.Account(fromAddress)
	require.NoError(t, err)

	sequenceNumber, err := accountInfo.SequenceNumber()
	require.NoError(t, err)

	gasInfo, err := client.EstimateGasPrice()
	require.NoError(t, err)

	rawTx := aptos.RawTransaction{
		Sender:         fromAddress,
		SequenceNumber: sequenceNumber,
		Payload:        payload,
		MaxGasAmount:   200000,
		GasUnitPrice:   gasInfo.GasEstimate,
		// TODO: handle expiry
		ExpirationTimestampSeconds: ledgerTimestamp + uint64(600),
		ChainId:                    chainId,
	}

	signingMessage, err := rawTx.SigningMessage()
	require.NoError(t, err)

	signature, err := keystore.Sign(context.Background(), fmt.Sprintf("%064x", publicKey), signingMessage)
	require.NoError(t, err)

	aptosPublicKey := aptoscrypto.Ed25519PublicKey{}
	err = aptosPublicKey.FromBytes([]byte(publicKey))
	require.NoError(t, err)

	aptosSignature := aptoscrypto.Ed25519Signature{}
	err = aptosSignature.FromBytes(signature)
	require.NoError(t, err)

	authenticator := &aptoscrypto.Ed25519Authenticator{
		PubKey: &aptosPublicKey,
		Sig:    &aptosSignature,
	}

	signedTx, err := rawTx.SignedTransactionWithAuthenticator(&aptoscrypto.AccountAuthenticator{
		Variant: aptoscrypto.AccountAuthenticatorEd25519,
		Auth:    authenticator,
	})
	require.NoError(t, err)

	submitResponse, err := client.SubmitTransaction(signedTx)
	require.NoError(t, err)

	return submitResponse
}

func waitForTx(t *testing.T, client *aptos.NodeClient, txHash string, duration time.Duration) {
	stopTime := time.Now().Add(duration)
	for time.Now().Before(stopTime) {
		time.Sleep(time.Second * 1)
		txInfo, err := client.TransactionByHash(txHash)
		if err == nil && txInfo.Type != aptosapi.TransactionVariantPending {
			return
		}
	}
	t.Fatalf("Failed to wait for transaction %s", txHash)
}
