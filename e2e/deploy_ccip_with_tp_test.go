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
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmslib "github.com/smartcontractkit/mcms"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool"
	link_token "github.com/smartcontractkit/chainlink-aptos/bindings/link-token"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	module_mcms "github.com/smartcontractkit/chainlink-aptos/bindings/mcms/mcms"
)

func Test_DeployCCIPTokenPool(t *testing.T) {
	localnet := false

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
		require.True(t, data.Success, data.VmStatus)
	}

	// Deploy MCMS
	mcmsSeed := mcms.DefaultSeed + time.Now().String()
	mcmsAddress, tx, mcmsContract, err := mcms.DeployToResourceAccount(deployerAccount, client, mcmsSeed)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("📃 Deployed MCMS contract at %v in tx %v\n", mcmsAddress.StringLong(), tx.Hash)

	// Deploy LINK token
	linkTokenObjectAddress, tx, boundLinkToken, err := link_token.DeployToObject(deployerAccount, client)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("Deployed LINK token to %v in tx %v\n", linkTokenObjectAddress.StringLong(), tx.Hash)

	// Initialize LINK token
	tx, err = boundLinkToken.LinkToken().Initialize(opts, nil, "LINK Token BnM", "LINK", 8, "", "")
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("LINK token initialized in tx %v\n", tx.Hash)

	linkTokenStateAddress := linkTokenObjectAddress.NamedObjectAddress([]byte("link::link_token::token_state"))
	fmt.Printf("LINK Token State address: %v\n", linkTokenStateAddress.StringLong())
	linkTokenMetadataAddress := linkTokenStateAddress.NamedObjectAddress([]byte("LINK"))
	fmt.Printf("LINK Token Metadata address: %v\n", linkTokenMetadataAddress.StringLong())

	// Mint some LINK
	tx, err = boundLinkToken.LinkToken().Mint(opts, deployerAccount.AccountAddress(), 10000000000)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("Minted 100 LINK to %v in tx %v\n", linkTokenObjectAddress.StringLong(), tx.Hash)

	// Deploy MCMS Registrar onto LINK token object
	tx, _, err = link_token.DeployMCMSRegistrarToExistingObject(deployerAccount, client, linkTokenObjectAddress, mcmsAddress, true)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("Deployed MCMS Registrar to object %v in tx %v\n", linkTokenObjectAddress.StringLong(), tx.Hash)

	// Transfer LINK token to MCMS
	linkTokenOwnerAddress := mcmsAddress.ResourceAccount(append([]byte("CHAINLINK_MCMS_EXISTING_OBJECT_REGISTRATION"), linkTokenObjectAddress[:]...))
	fmt.Printf("MCMS LINK Token Owner address: %v\n", linkTokenOwnerAddress.StringLong())
	tx, err = boundLinkToken.LinkToken().TransferOwnership(opts, linkTokenOwnerAddress)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("Initiated ownership transfer...")

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

	var (
		ccipObjectAddress aptos.AccountAddress
	)

	{
		// Build first proposal
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

		addToProposal := func(module bind.ModuleInformation, function string, _ []aptos.TypeTag, args [][]byte, err error) {
			require.NoError(t, err)
			if module.ModuleName == "link_token" {
				module.ModuleName = "mcms_token_registrar"
			}
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
		}

		// Accept ownership of MCMS
		addToProposal(mcmsContract.MCMSAccount().Encoder().AcceptOwnership())

		// Deploy CCIP
		ccipOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(ccip.DefaultSeed))
		require.NoError(t, err)
		ccipObjectAddress, err = mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(ccip.DefaultSeed))
		require.NoError(t, err)
		fmt.Printf("Deploying CCIP to %v\n", ccipObjectAddress.StringLong())

		ccipPayload, err := ccip.Compile(ccipObjectAddress, mcmsContract.Address(), true)
		require.NoError(t, err)
		chunks, err := bind.CreateChunks(ccipPayload, bind.ChunkSizeInBytes)
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
		addToProposal(ccipContract.FeeQuoter().Encoder().Initialize(1000, token, 12400, []aptos.AccountAddress{token}))
		addToProposal(onrampContract.Onramp().Encoder().Initialize(1234, deployerAccount.AccountAddress(), deployerAccount.AccountAddress(), []uint64{5678}, []aptos.AccountAddress{routerStateAddress}, []bool{false}))
		addToProposal(routerContract.Router().Encoder().SetOnRampVersions([]uint64{5678}, [][]byte{{1, 6, 0}}))
		addToProposal(ccipContract.FeeQuoter().Encoder().ApplyFeeTokenUpdates(nil, []aptos.AccountAddress{token}))
		addToProposal(ccipContract.FeeQuoter().Encoder().ApplyTokenTransferFeeConfigUpdates(5678, []aptos.AccountAddress{token}, []uint32{1}, []uint32{10000}, []uint16{0}, []uint32{1000}, []uint32{1000}, []bool{true}, nil))
		addToProposal(ccipContract.FeeQuoter().Encoder().ApplyDestChainConfigUpdates(5678, true, 1, 10000, 7000000, 0, 0, 0, 0, 0, 0, 0, evmFamilySelector, false, 0, 0, 1000000, 0, 10000000, 0))
		addToProposal(ccipContract.FeeQuoter().Encoder().ApplyPremiumMultiplierWeiPerEthUpdates([]aptos.AccountAddress{token}, []uint64{1}))
		// To be able to call fee_quoter::update_prices, need to register as an allowed offramp
		addToProposal(ccipContract.Auth().Encoder().ApplyAllowedOfframpUpdates(nil, []aptos.AccountAddress{ccipOwnerAddress}))
		addToProposal(ccipContract.FeeQuoter().Encoder().UpdatePrices([]aptos.AccountAddress{token}, []*big.Int{big.NewInt(1000)}, []uint64{5678}, []*big.Int{big.NewInt(0)}))

		// Accept ownership of LINK token
		addToProposal(boundLinkToken.LinkToken().Encoder().AcceptOwnership())

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

	// Execute ownership transfer of LINK token
	tx, err = boundLinkToken.LinkToken().ExecuteOwnershipTransfer(opts, linkTokenOwnerAddress)
	require.NoError(t, err)
	waitForTransaction(tx.Hash)
	fmt.Printf("Ownership transfer of LINK token executed\n")

	fmt.Println("Starting second proposal...")
	// Second proposal
	{
		inspector := aptossdk.NewInspector(client, aptossdk.TimelockRoleBypasser)
		opCount, err := inspector.GetOpCount(t.Context(), mcmsAddress.StringLong())
		require.NoError(t, err)
		validUntil := uint32(time.Now().Add(time.Hour).Unix())
		proposalBuilder := mcmslib.NewTimelockProposalBuilder().
			SetVersion("v1").
			SetValidUntil(validUntil).
			SetDescription("Second proposal").
			AddTimelockAddress(chainSelector, mcmsAddress.StringLong()).
			AddChainMetadata(chainSelector, mcmstypes.ChainMetadata{
				StartingOpCount:  opCount,
				MCMAddress:       mcmsAddress.StringLong(),
				AdditionalFields: Must(json.Marshal(aptossdk.AdditionalFieldsMetadata{Role: aptossdk.TimelockRoleBypasser})),
			}).
			SetAction(mcmstypes.TimelockActionBypass)

		addToProposal := func(module bind.ModuleInformation, function string, _ []aptos.TypeTag, args [][]byte, err error) {
			require.NoError(t, err)
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
		}

		// Deploy token pool on top of link token
		tokenPoolPayload, err := token_pool.Compile(linkTokenObjectAddress, ccipObjectAddress, mcmsAddress)
		require.NoError(t, err)
		chunks, err := bind.CreateChunks(tokenPoolPayload, bind.ChunkSizeInBytes)
		require.NoError(t, err)
		for i, chunk := range chunks {
			if i == len(chunks)-1 {
				addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, linkTokenObjectAddress))
				break
			}
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
		}

		// Deploy BurnMintTokenPool on top of link token
		burnMintTokenPoolPayload, err := burn_mint_token_pool.Compile(linkTokenObjectAddress, ccipObjectAddress, mcmsAddress, linkTokenObjectAddress, linkTokenMetadataAddress, true)
		require.NoError(t, err)
		chunks, err = bind.CreateChunks(burnMintTokenPoolPayload, bind.ChunkSizeInBytes)
		require.NoError(t, err)
		for i, chunk := range chunks {
			if i == len(chunks)-1 {
				addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, linkTokenObjectAddress))
				break
			}
			addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks))
		}

		timelockProposal, err := proposalBuilder.Build()
		require.NoError(t, err)
		convertersMap := map[mcmstypes.ChainSelector]mcmssdk.TimelockConverter{
			chainSelector: aptossdk.NewTimelockConverter(),
		}
		proposal, _, err := timelockProposal.Convert(t.Context(), convertersMap)
		require.NoError(t, err)

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
			fmt.Printf("TX executed: %v\n", result.Hash)
		}
		fmt.Println("🚀 All executed successfully")
	}
}
