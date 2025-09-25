package e2e

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmslib "github.com/smartcontractkit/mcms"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/managed_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/managed_token"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	module_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
)

var DestChainSelector = chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector

func Test_DeployCCIP(t *testing.T) {
	localnet := true

	deployerKey := &crypto.Ed25519PrivateKey{}
	require.NoError(t, deployerKey.FromHex(os.Getenv("DEPLOYER_KEY")))
	deployerAccount, err := aptos.NewAccountFromSigner(deployerKey)
	require.NoError(t, err)
	opts := &bind.TransactOpts{Signer: deployerAccount}

	var (
		client        *aptos.Client
		chainSelector mcmstypes.ChainSelector
	)
	if !localnet {
		client, err = aptos.NewClient(aptos.TestnetConfig)
		require.NoError(t, err)
		chainSelector = mcmstypes.ChainSelector(chain_selectors.APTOS_TESTNET.Selector)
	} else {
		client, err = aptos.NewClient(aptos.LocalnetConfig)
		require.NoError(t, err)
		err = client.Fund(deployerAccount.AccountAddress(), 10000000000)
		chainSelector = mcmstypes.ChainSelector(chain_selectors.APTOS_LOCALNET.Selector)
	}

	waitForTransaction := func(hash string) {
		data, err := client.WaitForTransaction(hash)
		require.NoError(t, err)
		require.True(t, data.Success, "transaction %v failed: %v", hash, data.VmStatus)
	}

	// Deploy MCMS
	mcmsSeed := mcms.DefaultSeed + time.Now().String()
	mcmsAddress, tx, mcmsContract, err := mcms.DeployToResourceAccount(deployerAccount, client, mcmsSeed)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)

	fmt.Printf("📃 Deployed MCMS Test contract at %v in tx %v\n", mcmsAddress.StringLong(), tx.Hash)

	// Configure MCMS
	signers := [2]common.Address{}
	signerKeys := [2]*ecdsa.PrivateKey{}
	for i := range signers {
		signerKeys[i], _ = ethcrypto.GenerateKey()
		signers[i] = ethcrypto.PubkeyToAddress(signerKeys[i].PublicKey)
	}
	slices.SortFunc(signers[:], func(a, b common.Address) int {
		return a.Cmp(b)
	})
	config := &mcmstypes.Config{
		Quorum:  2,
		Signers: []common.Address{signers[0], signers[1]},
	}
	configurer := aptossdk.NewConfigurer(client, deployerAccount, aptossdk.TimelockRoleBypasser)
	result, err := configurer.SetConfig(t.Context(), mcmsAddress.StringLong(), config, false)
	require.NoError(t, err)
	waitForTransaction(result.Hash)

	fmt.Printf("✅  Set bypasser config on MCMS contract\n")

	// Initiate ownership transfer
	tx, err = mcmsContract.MCMSAccount().TransferOwnershipToSelf(opts)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)

	fmt.Printf("↗️ Initiated ownership transfer of MCMS contract to itself\n")

	// Build proposal
	validUntil := uint32(time.Now().Add(time.Hour).Unix())
	proposalBuilder := mcmslib.NewTimelockProposalBuilder().
		SetVersion("v1").
		SetValidUntil(validUntil).
		SetDescription("First proposal").
		AddTimelockAddress(chainSelector, mcmsAddress.StringLong()).
		AddChainMetadata(chainSelector, mcmstypes.ChainMetadata{
			StartingOpCount:  0,
			MCMAddress:       mcmsAddress.StringLong(),
			AdditionalFields: Must(json.Marshal(aptossdk.AdditionalFieldsMetadata{Role: aptossdk.TimelockRoleBypasser})),
		}).
		SetAction(mcmstypes.TimelockActionBypass)

	opCounter := 0
	addToProposal := func(module bind.ModuleInformation, function string, _ []aptos.TypeTag, args [][]byte, err error) {
		transaction, err := aptossdk.NewTransaction(
			module.PackageName,
			module.ModuleName,
			function,
			module.Address,
			aptossdk.ArgsToData(args),
			"MCMS",
			nil,
		)
		require.NoError(t, err)
		proposalBuilder.AddOperation(mcmstypes.BatchOperation{
			ChainSelector: chainSelector,
			Transactions:  []mcmstypes.Transaction{transaction},
		})
		fmt.Printf("Added operation %v to proposal: %v::%v\n", opCounter, module.ModuleName, function)
		opCounter++
	}

	// Accept ownership of MCMS
	addToProposal(mcmsContract.MCMSAccount().Encoder().AcceptOwnership())

	// Deploy LINK token
	linkTokenSeed := "LINK_TOKEN"
	linkTokenObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(linkTokenSeed))
	require.NoError(t, err)
	fmt.Printf("Deploying LINK token to: %v\n", linkTokenObjectAddress.StringLong())
	linkTokenOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(linkTokenSeed))
	require.NoError(t, err)
	fmt.Printf("LINK token owner address: %v\n", linkTokenOwnerAddress.StringLong())

	linkTokenStateAddress := linkTokenObjectAddress.NamedObjectAddress([]byte("managed_token::managed_token::token_state"))
	fmt.Printf("LINK Token State address: %v\n", linkTokenStateAddress.StringLong())
	linkTokenMetadataAddress := linkTokenStateAddress.NamedObjectAddress([]byte("LINK"))
	fmt.Printf("LINK Token Metadata address: %v\n", linkTokenMetadataAddress.StringLong())

	linkTokenPayload, err := managed_token.Compile(linkTokenObjectAddress)
	require.NoError(t, err)
	chunks, err := bind.CreateChunks(linkTokenPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(linkTokenSeed)))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Deploy LINK MCMS Registrar
	mcmsRegistrarPayload, err := managed_token.CompileMCMSRegistrar(linkTokenObjectAddress, mcmsAddress, true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(mcmsRegistrarPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, linkTokenObjectAddress))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Initialize LINK token
	linkTokenContract := managed_token.Bind(linkTokenObjectAddress, client)
	maxSupply := big.NewInt(10000000000000)
	addToProposal(linkTokenContract.ManagedToken().Encoder().Initialize(&maxSupply, "LinkToken", "LINK", 8, "", ""))
	// Mint 10k LINK
	addToProposal(linkTokenContract.ManagedToken().Encoder().Mint(deployerAccount.Address, 1000000000000))

	// Deploy CCIP
	ccipOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(ccip.DefaultSeed))
	require.NoError(t, err)
	ccipObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(ccip.DefaultSeed))
	require.NoError(t, err)
	fmt.Printf("Deploying CCIP to %v\n", ccipObjectAddress.StringLong())

	ccipPayload, err := ccip.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(ccipPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(ccip.DefaultSeed)))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Deploy OnRamp
	onrampPayload, err := ccip_onramp.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(onrampPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Deploy OffRamp
	offrampPayload, err := ccip_offramp.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(offrampPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Deploy router
	routerPayload, err := ccip_router.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(routerPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Configure CCIP
	ccipContract := ccip.Bind(ccipObjectAddress, client)
	onrampContract := ccip_onramp.Bind(ccipObjectAddress, client)
	routerContract := ccip_router.Bind(ccipObjectAddress, client)
	// Ideally we'd call ccip_router::get_state_address here, but we can't as the contract isn't deployed yet...
	routerStateAddress := ccipObjectAddress.ResourceAccount([]byte("CHAINLINK_CCIP_ROUTER"))
	token := aptos.AccountAddress{}
	token.ParseStringRelaxed("0xa") // TODO replace with LINK token once deployed
	evmFamilySelector, _ := hex.DecodeString("2812d52c")

	addToProposal(ccipContract.RMNRemote().Encoder().Initialize(uint64(chainSelector)))
	addToProposal(ccipContract.FeeQuoter().Encoder().Initialize(big.NewInt(1000), token, 12400, []aptos.AccountAddress{token}))
	addToProposal(onrampContract.Onramp().Encoder().Initialize(uint64(chainSelector), deployerAccount.AccountAddress(), deployerAccount.AccountAddress(), []uint64{DestChainSelector}, []aptos.AccountAddress{routerStateAddress}, []bool{false}))
	addToProposal(routerContract.Router().Encoder().SetOnRampVersions([]uint64{DestChainSelector}, [][]byte{{1, 6, 0}}))
	addToProposal(ccipContract.FeeQuoter().Encoder().ApplyFeeTokenUpdates(nil, []aptos.AccountAddress{token}))
	addToProposal(ccipContract.FeeQuoter().Encoder().ApplyTokenTransferFeeConfigUpdates(DestChainSelector, []aptos.AccountAddress{token}, []uint32{1}, []uint32{10000}, []uint16{0}, []uint32{1000}, []uint32{1000}, []bool{true}, nil))
	addToProposal(ccipContract.FeeQuoter().Encoder().ApplyDestChainConfigUpdates(DestChainSelector, true, 1, 10000, 7000000, 0, 0, 0, 0, 0, 0, 0, evmFamilySelector, false, 0, 0, 1000000, 0, 10000000, 0))
	addToProposal(ccipContract.FeeQuoter().Encoder().ApplyPremiumMultiplierWeiPerEthUpdates([]aptos.AccountAddress{token}, []uint64{1}))
	// To be able to call fee_quoter::update_prices, need to register as an allowed offramp
	addToProposal(ccipContract.Auth().Encoder().ApplyAllowedOfframpUpdates(nil, []aptos.AccountAddress{ccipOwnerAddress}))
	feeTokenPrice := big.NewInt(1).Mul(big.NewInt(100), big.NewInt(1e18))
	addToProposal(ccipContract.FeeQuoter().Encoder().UpdatePrices([]aptos.AccountAddress{token}, []*big.Int{feeTokenPrice}, []uint64{DestChainSelector}, []*big.Int{big.NewInt(0)}))

	// Deploy token pool to a separate object
	// Deploy LINK token
	tokenPoolSeed := "LINK_TOKEN_POOL"
	tokenPoolObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(tokenPoolSeed))
	require.NoError(t, err)
	fmt.Printf("Deploying Token Pool token to: %v\n", tokenPoolObjectAddress.StringLong())
	tokenPoolOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(tokenPoolSeed))
	require.NoError(t, err)
	fmt.Printf("Token Pool owner address: %v\n", tokenPoolOwnerAddress.StringLong())

	// Deploy token pool to a new object
	tokenPoolPayload, err := token_pool.Compile(tokenPoolObjectAddress, ccipObjectAddress, mcmsAddress)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(tokenPoolPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(tokenPoolSeed)))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}

	// Deploy ManagedTokenPool on top of link token
	managedTokenPoolPayload, err := managed_token_pool.Compile(tokenPoolObjectAddress, ccipObjectAddress, mcmsAddress, tokenPoolObjectAddress, linkTokenObjectAddress, true)
	require.NoError(t, err)
	chunks, err = bind.CreateChunks(managedTokenPoolPayload, bind.ChunkSizeInBytes)
	require.NoError(t, err)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, tokenPoolObjectAddress))
			break
		}
		addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
	}
	managedTokenPoolContract := managed_token_pool.Bind(tokenPoolObjectAddress, client)
	managedTokenPoolStoreAddress := tokenPoolObjectAddress.ResourceAccount([]byte("CcipManagedTokenPool"))
	fmt.Printf("Deployed Managed Token Pool to: %v\n", tokenPoolObjectAddress.StringLong())
	fmt.Printf("\tStore resource account address: %v\n", managedTokenPoolStoreAddress)
	addToProposal(linkTokenContract.ManagedToken().Encoder().ApplyAllowedMinterUpdates(nil, []aptos.AccountAddress{managedTokenPoolStoreAddress}))
	addToProposal(linkTokenContract.ManagedToken().Encoder().ApplyAllowedBurnerUpdates(nil, []aptos.AccountAddress{managedTokenPoolStoreAddress}))

	// Set up CCIP
	addToProposal(ccipContract.FeeQuoter().Encoder().ApplyDestChainConfigUpdates(
		DestChainSelector,
		true,
		10,
		30_000,
		3_000_000,
		300_000,
		16,
		40,
		3000,
		100,
		16,
		1,
		[]byte{0x28, 0x12, 0xd5, 0x2c},
		false,
		25,
		90_000,
		200_000,
		11e8,
		0,
		10,
	))
	addToProposal(managedTokenPoolContract.ManagedTokenPool().Encoder().ApplyChainUpdates(nil, []uint64{DestChainSelector}, [][][]byte{{common.HexToAddress("0x1111111B536498Bcd6326722E5Fd22D8234F1c7C").Bytes()}}, [][]byte{common.LeftPadBytes(common.HexToAddress("0x222222aF075ef84856A4DF03555E9777b2d227f6").Bytes(), 32)}))
	addToProposal(managedTokenPoolContract.ManagedTokenPool().Encoder().SetChainRateLimiterConfig(DestChainSelector, false, 0, 0, false, 0, 0))
	// Set Administrator and call set_pool
	addToProposal(ccipContract.TokenAdminRegistry().Encoder().ProposeAdministrator(linkTokenMetadataAddress, ccipOwnerAddress))
	addToProposal(ccipContract.TokenAdminRegistry().Encoder().AcceptAdminRole(linkTokenMetadataAddress))
	addToProposal(ccipContract.TokenAdminRegistry().Encoder().SetPool(linkTokenMetadataAddress, tokenPoolObjectAddress))

	// Build, setRoot and execute proposal
	timelockProposal, err := proposalBuilder.Build()
	require.NoError(t, err)
	convertersMap := map[mcmstypes.ChainSelector]mcmssdk.TimelockConverter{
		chainSelector: aptossdk.NewTimelockConverter(),
	}
	proposal, _, err := timelockProposal.Convert(t.Context(), convertersMap)
	require.NoError(t, err)

	inspector := aptossdk.NewInspector(client, aptossdk.TimelockRoleBypasser)
	inspectorsMap := map[mcmstypes.ChainSelector]mcmssdk.Inspector{
		chainSelector: inspector,
	}
	signable, err := mcmslib.NewSignable(&proposal, inspectorsMap)
	require.NoError(t, err)
	_, err = signable.SignAndAppend(mcmslib.NewPrivateKeySigner(signerKeys[0]))
	require.NoError(t, err)
	_, err = signable.SignAndAppend(mcmslib.NewPrivateKeySigner(signerKeys[1]))
	require.NoError(t, err)

	encoders, err := proposal.GetEncoders()
	require.NoError(t, err)
	aptosEncoder := encoders[chainSelector].(*aptossdk.Encoder)
	executorsMap := map[mcmstypes.ChainSelector]mcmssdk.Executor{
		chainSelector: aptossdk.NewExecutor(client, deployerAccount, aptosEncoder, aptossdk.TimelockRoleBypasser),
	}
	executable, err := mcmslib.NewExecutable(&proposal, executorsMap)
	require.NoError(t, err)

	fmt.Println("⏳ Proposal built, starting execution...")
	// Set Root
	result, err = executable.SetRoot(t.Context(), chainSelector)
	require.NoError(t, err)
	waitForTransaction(result.Hash)
	fmt.Printf("✅  Set root in tx %v\n", result.Hash)

	// Execute
	decoder := aptossdk.NewDecoder()
	for i, op := range proposal.Operations {
		// Decode operation
		decodedOp, err := decoder.Decode(op.Transaction, module_mcms.FunctionInfo)
		require.NoError(t, err)
		method, args, err := decodedOp.String()
		require.NoError(t, err)
		fmt.Printf("Executing Operation %d (%v):\n", i, method)
		fmt.Println(args)

		result, err = executable.Execute(t.Context(), i)
		require.NoError(t, err)
		waitForTransaction(result.Hash)
	}
	fmt.Println("🚀 All executed successfully")
}

func Test_CCIPSend(t *testing.T) {
	localnet := true

	deployerKey := &crypto.Ed25519PrivateKey{}
	require.NoError(t, deployerKey.FromHex(os.Getenv("DEPLOYER_KEY")))
	deployerAccount, err := aptos.NewAccountFromSigner(deployerKey)
	require.NoError(t, err)
	opts := &bind.TransactOpts{Signer: deployerAccount}

	var (
		client *aptos.Client
	)
	if !localnet {
		client, err = aptos.NewClient(aptos.TestnetConfig)
		require.NoError(t, err)
	} else {
		client, err = aptos.NewClient(aptos.LocalnetConfig)
		require.NoError(t, err)
		err = client.Fund(deployerAccount.AccountAddress(), 10000000000)
	}

	ccipAddress := aptos.AccountAddress{}
	_ = ccipAddress.ParseStringRelaxed("0xcac225f8bca207cccefb15ad1f3bbdfa475c17e53905800dcf3e88d2c6578f31")

	feeTokenAddress := aptos.AccountAddress{}
	_ = feeTokenAddress.ParseStringRelaxed("0xa")

	linkTokenAddress := aptos.AccountAddress{}
	_ = linkTokenAddress.ParseStringRelaxed("0x74050880bfa2c086f5765f1ee49dfd948053a4e7696582e8d9ad2504ece194a9")

	tokenStoreAddress := aptos.AccountAddress{}

	toAddress := common.LeftPadBytes(common.HexToAddress("0x90392A1E8A941098a3C75E0BDB172cFdE7E4f1f4").Bytes(), 32)

	extraArgs := MakeBCSEVMExtraArgsV2(big.NewInt(100), false)

	ccipRouterContract := ccip_router.Bind(ccipAddress, client)
	fee, err := ccipRouterContract.Router().GetFee(nil, DestChainSelector, toAddress, []byte("Hello, world!"), []aptos.AccountAddress{linkTokenAddress}, []uint64{1e8}, []aptos.AccountAddress{tokenStoreAddress}, feeTokenAddress, aptos.AccountZero, extraArgs)
	require.NoError(t, err)
	fmt.Printf("Estimated fee: %v\n", fee)

	tx, err := ccipRouterContract.Router().CCIPSend(opts, DestChainSelector, toAddress, []byte("Hello, world!"), []aptos.AccountAddress{linkTokenAddress}, []uint64{1e8}, []aptos.AccountAddress{tokenStoreAddress}, feeTokenAddress, aptos.AccountZero, extraArgs)
	require.NoError(t, err)
	data, err := client.WaitForTransaction(tx.Hash)
	require.NoError(t, err)
	require.True(t, data.Success, "transaction %v failed: %v", tx.Hash, data.VmStatus)

	fmt.Println("CCIP Message sent in transaction:", tx.Hash)

	for i, event := range data.Events {
		fmt.Println("Event", i, event.Type)
		fmt.Printf("%+v\n", event.Data)
	}
}

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}

	return t
}

const GenericExtraArgsV2Tag = "0x181dcf10"

// MakeBCSEVMExtraArgsV2 makes the BCS encoded extra args for a message sent from an Move based chain that is destined for an EVM chain.
// The extra args are used to specify the gas limit and allow out of order flag for the message.
func MakeBCSEVMExtraArgsV2(gasLimit *big.Int, allowOOO bool) []byte {
	s := &bcs.Serializer{}
	s.U256(*gasLimit)
	s.Bool(allowOOO)
	return append(hexutil.MustDecode(GenericExtraArgsV2Tag), s.ToBytes()...)
}
