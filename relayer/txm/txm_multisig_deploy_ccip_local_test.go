//go:build integration

package txm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"

	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/testutils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

var (
	deployClient      aptos.AptosRpcClient
	deployMcmsAccount aptos.AccountAddress
	deployMcmsAddress string
	deployChainIdBig  *big.Int
	deployNextNonce   uint64 = 0
	deployPostOpCount uint64 = 0
	deployPreOpCount  uint64 = 0
)

const (
	// ChunkSize defines the maximum size of bytecode/metadata chunks
	CHUNK_SIZE = 8500
)

func getDeployNextNonce() uint64 {
	nonce := deployNextNonce
	deployNextNonce++
	return nonce
}

func getDeployPreOpCount() uint64 {
	return deployPostOpCount
}

func getDeployCumulativePostOpCount(opCount uint64) uint64 {
	deployPostOpCount += opCount
	return deployPostOpCount
}

// TestDeployLargeContractInChunks tests the deployment of a large contract (CCIP)
// via MCMS using code chunking.
func TestDeployMCMSAndCCIPInChunks(t *testing.T) {
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

	runDeployMCMSAndCCIPInChunks(t, logger, rpcUrl, keystore, accounts)
}

func chunkMetadata(metadata []byte, chunkSize int) []TimelockOperation {
	var ops []TimelockOperation
	for i := 0; i < len(metadata); i += chunkSize {
		end := i + chunkSize
		if end > len(metadata) {
			end = len(metadata)
		}
		chunk := metadata[i:end]

		// Use the 3-parameter version for stage_code_chunk
		data, err := SerializeStageCodeChunkParams(chunk, []uint16{}, [][]byte{})
		if err != nil {
			panic(err)
		}
		ops = append(ops, TimelockOperation{
			Target:       deployMcmsAccount,
			ModuleName:   "mcms_deployer",
			FunctionName: "stage_code_chunk",
			Data:         data,
		})
	}
	return ops
}

func chunkBytecode(modules [][]byte, chunkSize int) []TimelockOperation {
	var ops []TimelockOperation
	for i := 0; i < len(modules); i += chunkSize {
		end := i + chunkSize
		if end > len(modules) {
			end = len(modules)
		}
		chunks := modules[i:end]

		// Create code indices for this chunk
		var indices []uint16
		for j := 0; j < len(chunks); j++ {
			indices = append(indices, uint16(i+j))
		}

		// Use the 3-parameter version for stage_code_chunk
		data, err := SerializeStageCodeChunkParams([]byte{}, indices, chunks)
		if err != nil {
			panic(err)
		}
		ops = append(ops, TimelockOperation{
			Target:       deployMcmsAccount,
			ModuleName:   "mcms_deployer",
			FunctionName: "stage_code_chunk",
			Data:         data,
		})
	}
	return ops
}

func scheduleAndExecuteOperations(
	t *testing.T,
	logger logger.Logger,
	txm *AptosTxm,
	operations []TimelockOperation,
	proposerSigners []Signer,
	deployerAddress string,
	deployerPublicKeyHex string,
	role uint8,
	chainID *big.Int,
	delay uint64,
	salt []byte,
	simulateTx bool,
) {
	predecessor := make([]byte, 32) // ZERO_HASH

	// Set up root metadata
	rootMetadata := RootMetadata{
		Role:                 role,
		ChainID:              chainID,
		MultiSig:             deployMcmsAccount,
		PreOpCount:           getDeployPreOpCount(),
		PostOpCount:          getDeployCumulativePostOpCount(uint64(len(operations))),
		OverridePreviousRoot: true,
	}

	// Convert timelock operations to multiple operations
	ops := deployTimelockOpToMultipleOps(operations, predecessor, salt, delay, role, chainID)

	// Generate merkle tree and set root
	merkleTree, err := GenerateMerkleTree(ops, rootMetadata)
	if err != nil {
		t.Fatalf("Failed to generate merkle tree: %v", err)
	}

	setRootId := EnqueueSetRoot(t, logger, merkleTree, txm, rootMetadata, proposerSigners,
		deployerAddress, deployerPublicKeyHex, deployMcmsAddress)
	waitForTxmId(t, txm, setRootId, time.Second*30)

	// Schedule each operation through MCMS
	for i, op := range operations {
		proof := merkleTree.GetProof(i + 1)
		hashOp, err := HashOp(&ops[i])
		require.NoError(t, err)
		require.True(t, merkleTree.VerifyProof(proof, hashOp))
		txId := ScheduleSingleOperationAsDeployer(t, logger, txm, deployMcmsAccount,
			deployerAddress, deployerPublicKeyHex, []TimelockOperation{op},
			predecessor, salt, delay, role, chainID, ops[i].Nonce, proof, simulateTx)
		waitForTxmId(t, txm, txId, time.Second*30)
	}

	// Wait for the timelock delay
	time.Sleep(time.Duration(delay) * time.Second)

	// Execute each operation
	for i := 0; i < len(operations); i++ {
		txId := ExecuteBatchOperations(t, txm, deployMcmsAddress, deployerAddress,
			deployerPublicKeyHex, []TimelockOperation{operations[i]}, predecessor, salt, simulateTx)
		waitForTxmId(t, txm, txId, time.Second*30)
	}
}

// runDeployMCMSAndCCIPInChunks contains the core logic for deploying
// the CCIP contract via MCMS chunks.
func runDeployMCMSAndCCIPInChunks(t *testing.T, logger logger.Logger, rpcURL string, keystore loop.Keystore, accounts []Account) {
	// Generate proposer signers for the test
	proposerSigners := GenerateSigners(t, 3)
	for _, signer := range proposerSigners {
		logger.Debugw("Generated proposer signer", "address", hex.EncodeToString(signer.Address))
	}

	deployer := accounts[0]
	deployerAddress := deployer.accountAddress.String()
	deployerPublicKeyHex := hex.EncodeToString([]byte(deployer.publicKey))

	// Use a random seed for the MCMS resource account
	mcmsSeed := make([]byte, 64)
	_, err := rand.Read(mcmsSeed)
	require.NoError(t, err)

	deployMcmsAccount = deployer.accountAddress.ResourceAccount(mcmsSeed)
	deployMcmsAddress = deployMcmsAccount.String()

	logger.Debugw("MCMS resource account", "address", deployMcmsAddress)

	// Compile and deploy the MCMS contract
	mcmsPackageMetadataBytes, mcmsModuleBytecodeBytes := compileMcmsContract(t, deployMcmsAccount, deployer.accountAddress)

	client, err := aptos.NewNodeClient(rpcURL, 0)
	require.NoError(t, err)
	deployClient = client

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "3",
		NetworkName:     "testnet",
	}
	rlClient := ratelimit.NewRateLimitedClient(client, chainInfo, rpcURL, 100, 30*time.Second)
	getClient := func() (aptos.AptosRpcClient, error) {
		return rlClient, nil
	}

	chainId, err := client.GetChainId()
	require.NoError(t, err)
	deployChainIdBig = new(big.Int).SetUint64(uint64(chainId))

	config := DefaultConfigSet
	txm, err := New(logger, keystore, config, getClient, chainInfo.ChainID)
	require.NoError(t, err)
	err = txm.Start(context.Background())
	require.NoError(t, err)

	// Deploy MCMS module
	deployId := uuid.New().String()
	err = txm.Enqueue(
		deployId,
		getSampleTxMetadata(),
		deployerAddress,
		deployerPublicKeyHex,
		"0x1::resource_account::create_resource_account_and_publish_package",
		/* typeArgs= */ []string{},
		/* paramTypes= */ []string{"vector<u8>", "vector<u8>", "vector<vector<u8>>"},
		/* paramValues= */ []any{mcmsSeed, mcmsPackageMetadataBytes, mcmsModuleBytecodeBytes},
		/* simulateTx= */ false,
	)
	require.NoError(t, err)
	waitForTxmId(t, txm, deployId, time.Second*30)

	role := uint8(PROPOSER_ROLE)
	SetupInitialConfigAsDeployer(t, logger, txm, role, proposerSigners, deployerAddress, deployerPublicKeyHex, true, deployMcmsAddress, false)
	TransferOwnership(t, txm, deployerAddress, deployerPublicKeyHex, deployMcmsAddress, false)

	// Create a unique seed for the new object owner
	newOwnerSeed := make([]byte, 32)
	_, err = rand.Read(newOwnerSeed)
	require.NoError(t, err)

	// --- Get the expected code object address directly from the Move view function ---
	seedArg, err := bcs.SerializeBytes(newOwnerSeed)
	require.NoError(t, err, "Failed to serialize newOwnerSeed for view call")

	// Call mcms::mcms_registry::get_new_code_object_address
	codeObjectAddressPayload := CreateViewPayload(deployMcmsAddress, "mcms_registry", "get_new_code_object_address",
		[]aptos.TypeTag{}, [][]byte{seedArg})
	viewResult, err := deployClient.View(codeObjectAddressPayload)
	require.NoError(t, err, "Failed to call get_new_code_object_address view function")

	returnedAddrHex, ok := viewResult[0].(string)
	require.True(t, ok, "Expected address string from view function result")
	var ccipObjectAddress aptos.AccountAddress
	err = ccipObjectAddress.ParseStringRelaxed(returnedAddrHex)
	require.NoError(t, err, "Failed to parse address returned by view function")
	logger.Debugw("ccipObjectAddress", "ccipObjectAddress", ccipObjectAddress.String())

	namedAddresses := GetNamedAddresses(ccipObjectAddress, deployMcmsAccount)
	compileResult := testutils.CompileMovePackage(t, filepath.Join("ccip", "ccip"), namedAddresses)

	// 1. Create accept ownership operation
	acceptOwnershipOp := TimelockOperation{
		Target:       deployMcmsAccount,
		ModuleName:   "mcms_account",
		FunctionName: "accept_ownership",
		Data:         []byte{},
	}

	// 2. Create metadata chunk operations
	metadataOps := chunkMetadata(compileResult.PackageMetadata, CHUNK_SIZE)

	// 3. Create bytecode module chunk operations
	moduleOps := chunkBytecode(compileResult.BytecodeModules, CHUNK_SIZE)

	// 4. Create final publish operation with remaining data (if any)
	// The approach: use stage_code_chunk_and_publish_to_object to publish all staged chunks
	// For a complete chunked approach, we end with empty final data since all chunks are already staged
	// Move contract function expects to stage final chunks AND publish
	// So we pass empty parameters to trigger publish of already-staged chunks
	publishData, err := SerializeStageCodeChunkAndPublishParams([]byte{}, []uint16{}, [][]byte{}, newOwnerSeed)
	if err != nil {
		t.Fatalf("Failed to serialize stage_code_chunk_and_publish_to_object params: %v", err)
	}
	publishOp := TimelockOperation{
		Target:       deployMcmsAccount,
		ModuleName:   "mcms_deployer",
		FunctionName: "stage_code_chunk_and_publish_to_object",
		Data:         publishData,
	}

	// Combine all operations
	allOperations := []TimelockOperation{acceptOwnershipOp}
	allOperations = append(allOperations, metadataOps...)
	allOperations = append(allOperations, moduleOps...)
	allOperations = append(allOperations, publishOp)

	// Schedule and execute operations
	delay := uint64(TEST_DELAY)
	salt := []byte{} // Empty salt for initial deployment
	scheduleAndExecuteOperations(t, logger, txm, allOperations, proposerSigners, deployerAddress, deployerPublicKeyHex, role, deployChainIdBig, delay, salt, false)

	// Verify deployment was successful
	receiverRegistryTypeAndVersionPayload := CreateViewPayload(ccipObjectAddress.String(), "receiver_registry", "type_and_version",
		[]aptos.TypeTag{}, [][]byte{})
	result, err := deployClient.View(receiverRegistryTypeAndVersionPayload)
	require.NoError(t, err)

	version := result[0].(string)
	require.Equal(t, version, "ReceiverRegistry 1.6.0")
	logger.Debugw("Successfully deployed receiver_registry module via chunks", "version", result)

	// ---------------------------------------------
	// Now test upgrading the contract with a new version
	// ---------------------------------------------
	logger.Infow("Starting contract upgrade test", "currentVersion", version)

	projectRoot, err := filepath.Abs("../..")
	require.NoError(t, err)

	// Directly modify the existing receiver_registry.move file
	receiverRegistryFilePath := filepath.Join(projectRoot, "contracts", "ccip", "ccip", "sources", "receiver_registry.move")
	logger.Debugw("Using absolute path for receiver_registry.move", "path", receiverRegistryFilePath)

	// Read and backup the original content
	originalContent, err := os.ReadFile(receiverRegistryFilePath)
	require.NoError(t, err)

	// Create backup file
	backupFilePath := receiverRegistryFilePath + ".bak"
	err = os.WriteFile(backupFilePath, originalContent, 0644)
	require.NoError(t, err)

	// Replace the version string
	modifiedContent := bytes.Replace(
		originalContent,
		[]byte(version),
		[]byte("ReceiverRegistry 2.0"),
		1,
	)

	// Write the modified content
	err = os.WriteFile(receiverRegistryFilePath, modifiedContent, 0644)
	require.NoError(t, err)

	// Make sure to restore the original file at the end of the test
	defer func() {
		// Restore the original file content
		err := os.WriteFile(receiverRegistryFilePath, originalContent, 0644)
		if err != nil {
			logger.Errorw("Failed to restore original receiver_registry.move file", "error", err)
		} else {
			logger.Debugw("Successfully restored original receiver_registry.move file")
		}

		// Remove the backup file
		_ = os.Remove(backupFilePath)
	}()

	logger.Debugw("Modified existing receiver_registry.move file for upgrade test", "path", receiverRegistryFilePath)

	upgradeCompileResult := testutils.CompileMovePackage(t, filepath.Join("ccip", "ccip"), namedAddresses)

	// Create upgrade operations
	upgradeMetadataOps := chunkMetadata(upgradeCompileResult.PackageMetadata, CHUNK_SIZE)
	upgradeModuleOps := chunkBytecode(upgradeCompileResult.BytecodeModules, CHUNK_SIZE)

	// Create final upgrade operation
	upgradeData, err := serializeStageCodeChunkAndUpgradeObjectCodeParams([]byte{}, []uint16{}, [][]byte{}, ccipObjectAddress)
	require.NoError(t, err)
	upgradeOp := TimelockOperation{
		Target:       deployMcmsAccount,
		ModuleName:   "mcms_deployer",
		FunctionName: "stage_code_chunk_and_upgrade_object_code",
		Data:         upgradeData,
	}

	// Combine all upgrade operations
	allUpgradeOps := []TimelockOperation{}
	allUpgradeOps = append(allUpgradeOps, upgradeMetadataOps...)
	allUpgradeOps = append(allUpgradeOps, upgradeModuleOps...)
	allUpgradeOps = append(allUpgradeOps, upgradeOp)

	// Schedule and execute upgrade operations (with unique salt)
	upgradeSalt := []byte("upgrade") // Use a different salt for the upgrade
	scheduleAndExecuteOperations(t, logger, txm, allUpgradeOps, proposerSigners,
		deployerAddress, deployerPublicKeyHex, role, deployChainIdBig, delay, upgradeSalt, false)

	// Verify upgrade was successful
	updatedVersionPayload := CreateViewPayload(ccipObjectAddress.String(), "receiver_registry", "type_and_version",
		[]aptos.TypeTag{}, [][]byte{})
	updatedResult, err := deployClient.View(updatedVersionPayload)
	require.NoError(t, err)

	updatedVersion := updatedResult[0].(string)
	require.Equal(t, "ReceiverRegistry 2.0", updatedVersion)
	logger.Infow("Successfully upgraded receiver_registry module", "previousVersion", version, "newVersion", updatedVersion)
}

// serializeStageCodeChunkAndUpgradeObjectCodeParams serializes parameters for mcms_deployer::stage_code_chunk_and_upgrade_object_code
func serializeStageCodeChunkAndUpgradeObjectCodeParams(metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, codeObjectAddress aptos.AccountAddress) ([]byte, error) {
	return bcs.SerializeSingle(func(ser *bcs.Serializer) {
		// metadata_chunk: vector<u8>
		ser.WriteBytes(metadataChunk)

		// code_indices: vector<u16>
		ser.Uleb128(uint32(len(codeIndices)))
		for _, idx := range codeIndices {
			ser.U16(idx)
		}

		// code_chunks: vector<vector<u8>>
		ser.Uleb128(uint32(len(codeChunks)))
		for _, chunk := range codeChunks {
			ser.WriteBytes(chunk)
		}

		// code_object_address: address (required for upgrade)
		ser.Struct(&codeObjectAddress)
	})
}

// deployTimelockOpToMultipleOps is a custom version of timelockOpToMulitpleOps that uses our deploy-prefixed variables
func deployTimelockOpToMultipleOps(tlOps []TimelockOperation, predecessor []byte, salt []byte, delay uint64, role uint8, chainId *big.Int) []Op {
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
			MultiSig:     deployMcmsAccount,
			Nonce:        getDeployNextNonce(),
			To:           deployMcmsAccount,
			ModuleName:   "mcms",
			FunctionName: "timelock_schedule_batch",
			Data:         serializedData,
		}
	}
	return ops
}

func GetNamedAddresses(ccipObjectAddress, deployMcmsAccount aptos.AccountAddress) map[string]aptos.AccountAddress {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipObjectAddress,
		"mcms":                      deployMcmsAccount,
		"mcms_register_entrypoints": deployMcmsAccount,
	}

	return namedAddresses
}
