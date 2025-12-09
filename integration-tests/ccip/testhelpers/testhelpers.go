package testhelpers

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strconv"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	chain_selectors "github.com/smartcontractkit/chain-selectors"
	mcmslib "github.com/smartcontractkit/mcms"
	mcmssdk "github.com/smartcontractkit/mcms/sdk"
	aptossdk "github.com/smartcontractkit/mcms/sdk/aptos"
	mcmstypes "github.com/smartcontractkit/mcms/types"

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
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type CCIPDeployment struct {
	MCMSAddress      aptos.AccountAddress
	CCIPAddress      aptos.AccountAddress
	LINKAddress      aptos.AccountAddress
	TokenPoolAddress aptos.AccountAddress
}

var destChainSelector = chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector

func DeployCCIP(ctx context.Context, lggr logger.Logger, deployer *aptos.Account, rpcClient aptos.AptosRpcClient) (CCIPDeployment, error) {
	opts := &bind.TransactOpts{Signer: deployer}
	chainID, err := rpcClient.GetChainId()
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get chain ID from RPC client: %w", err)
	}
	chainDetails, err := chain_selectors.GetChainDetailsByChainIDAndFamily(strconv.Itoa(int(chainID)), chain_selectors.FamilyAptos)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("could not detect chain selector from chain ID %v: %w", chainID, err)
	}
	aptosChainSelector := mcmstypes.ChainSelector(chainDetails.ChainSelector)

	// Helper function to wait for a transaction to be mined and check its status
	waitForTransaction := func(err error, tx *api.PendingTransaction) error {
		if err != nil {
			return fmt.Errorf("failed to create transaction: %w", err)
		}
		data, err := rpcClient.WaitForTransaction(tx.Hash)
		if err != nil {
			return fmt.Errorf("failed to wait for transaction %v: %w", tx.Hash, err)
		}
		if !data.Success {
			return fmt.Errorf("transaction %v failed: %v", tx.Hash, data.VmStatus)
		}
		return nil
	}

	// Deploy MCMS
	mcmsSeed := mcms.DefaultSeed + time.Now().String()
	mcmsAddress, tx, mcmsContract, err := mcms.DeployToResourceAccount(deployer, rpcClient, mcmsSeed)
	if err := waitForTransaction(err, tx); err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to deploy MCMS: %w", err)
	}
	lggr.Infof("📃 Deployed MCMS to %v in tx %v", mcmsAddress.StringLong(), tx.Hash)

	// Configure MCMS - use two random signers
	signers := [2]common.Address{}
	signerKeys := [2]*ecdsa.PrivateKey{}
	for i := range signers {
		signerKeys[i], _ = ethcrypto.GenerateKey()
		signers[i] = ethcrypto.PubkeyToAddress(signerKeys[i].PublicKey)
	}
	// Signers must be sorted by address
	slices.SortFunc(signers[:], func(a, b common.Address) int {
		return a.Cmp(b)
	})
	config := &mcmstypes.Config{
		Quorum:  2,
		Signers: []common.Address{signers[0], signers[1]},
	}
	configurer := aptossdk.NewConfigurer(rpcClient, deployer, aptossdk.TimelockRoleBypasser)
	result, err := configurer.SetConfig(ctx, mcmsAddress.StringLong(), config, false)
	if waitForTransaction(err, &api.PendingTransaction{Hash: result.Hash}) != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to set config on MCMS contract %v: %w", mcmsAddress.StringLong(), err)
	}
	lggr.Debugf("✅ Set bypasser config on MCMS contract %v", mcmsAddress.StringLong())
	// Initiate ownership transfer
	tx, err = mcmsContract.MCMSAccount().TransferOwnershipToSelf(opts)
	if waitForTransaction(err, tx) != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to transfer ownership of MCMs to itself: %w", err)
	}
	lggr.Debugf("↗️ Initiated ownership transfer of MCMS contract to itself")

	// Build proposal
	validUntil := uint32(time.Now().Add(time.Hour).Unix())
	afMetadata, _ := json.Marshal(aptossdk.AdditionalFieldsMetadata{Role: aptossdk.TimelockRoleBypasser})
	proposalBuilder := mcmslib.NewTimelockProposalBuilder().
		SetVersion("v1").
		SetValidUntil(validUntil).
		SetDescription("First proposal").
		AddTimelockAddress(aptosChainSelector, mcmsAddress.StringLong()).
		AddChainMetadata(aptosChainSelector, mcmstypes.ChainMetadata{
			StartingOpCount:  0,
			MCMAddress:       mcmsAddress.StringLong(),
			AdditionalFields: afMetadata,
		}).
		SetAction(mcmstypes.TimelockActionBypass)

	opCounter := 0
	addToProposal := func(module bind.ModuleInformation, function string, _ []aptos.TypeTag, args [][]byte, err error) error {
		transaction, err := aptossdk.NewTransaction(
			module.PackageName,
			module.ModuleName,
			function,
			module.Address,
			aptossdk.ArgsToData(args),
			"MCMS",
			nil,
		)
		if err != nil {
			return fmt.Errorf("failed to add transaction %s::%s::%s to proposal: %w", module.PackageName, module.ModuleName, function, err)
		}
		proposalBuilder.AddOperation(mcmstypes.BatchOperation{
			ChainSelector: aptosChainSelector,
			Transactions:  []mcmstypes.Transaction{transaction},
		})
		lggr.Debugf("Added operation %v to proposal: %s::%s::%s", opCounter, module.PackageName, module.ModuleName, function)
		opCounter++
		return nil
	}

	// Accept MCMS ownership of itself
	if addToProposal(mcmsContract.MCMSAccount().Encoder().AcceptOwnership()) != nil {
		return CCIPDeployment{}, err
	}

	// Deploy LINK token
	linkTokenSeed := "LINK_TOKEN"
	linkTokenObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(linkTokenSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object address for seed %v: %w", linkTokenSeed, err)
	}
	lggr.Infof("🪙 Deploying LINK token to: %v", linkTokenObjectAddress.StringLong())
	linkTokenOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(linkTokenSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object owner address for seed %v: %w", linkTokenSeed, err)
	}
	lggr.Debugf("LINK token owner address: %v", linkTokenOwnerAddress.StringLong())

	linkTokenStateAddress := linkTokenObjectAddress.NamedObjectAddress([]byte("managed_token::managed_token::token_state"))
	lggr.Debugf("LINK Token State address: %v", linkTokenStateAddress.StringLong())
	linkTokenMetadataAddress := linkTokenStateAddress.NamedObjectAddress([]byte("LINK"))
	lggr.Debugf("LINK Token Metadata address: %v", linkTokenMetadataAddress.StringLong())

	linkTokenPayload, err := managed_token.Compile(linkTokenObjectAddress)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile managed token: %w", err)
	}
	chunks, _ := bind.CreateChunks(linkTokenPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(linkTokenSeed))) != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)) != nil {
			return CCIPDeployment{}, err
		}
	}

	// Deploy LINK MCMS Registrar
	mcmsRegistrarPayload, err := managed_token.CompileMCMSRegistrar(linkTokenObjectAddress, mcmsAddress, true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile managed token MCMS registrar: %w", err)
	}
	chunks, _ = bind.CreateChunks(mcmsRegistrarPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, linkTokenObjectAddress)) != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)) != nil {
			return CCIPDeployment{}, err
		}
	}

	// Initialize LINK token
	linkTokenContract := managed_token.Bind(linkTokenObjectAddress, rpcClient)
	if addToProposal(linkTokenContract.ManagedToken().Encoder().Initialize(nil, "LinkToken", "LINK", 8, "", "")) != nil {
		return CCIPDeployment{}, err
	}
	// Mint 10k LINK
	if addToProposal(linkTokenContract.ManagedToken().Encoder().Mint(deployer.AccountAddress(), 10_000e8)) != nil {
		return CCIPDeployment{}, err
	}

	// Deploy CCIP
	ccipOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(ccip.DefaultSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object owner address for seed %v: %w", ccip.DefaultSeed, err)
	}
	ccipObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(ccip.DefaultSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object address for seed %v: %w", ccip.DefaultSeed, err)
	}
	lggr.Infof("🔗 Deploying CCIP to %v", ccipObjectAddress.StringLong())

	ccipPayload, err := ccip.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile ccip: %w", err)
	}
	chunks, _ = bind.CreateChunks(ccipPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(ccip.DefaultSeed))); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}

	// Deploy OnRamp
	onrampPayload, err := ccip_onramp.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile ccip onramp: %w", err)
	}
	chunks, _ = bind.CreateChunks(onrampPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress)); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}

	// Deploy OffRamp
	offrampPayload, err := ccip_offramp.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile ccip offramp: %w", err)
	}
	chunks, _ = bind.CreateChunks(offrampPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress)); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}

	// Deploy router
	routerPayload, err := ccip_router.Compile(ccipObjectAddress, mcmsContract.Address(), true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile ccip router: %w", err)
	}
	chunks, _ = bind.CreateChunks(routerPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, ccipObjectAddress)); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}

	// Configure CCIP
	ccipContract := ccip.Bind(ccipObjectAddress, rpcClient)
	onrampContract := ccip_onramp.Bind(ccipObjectAddress, rpcClient)
	routerContract := ccip_router.Bind(ccipObjectAddress, rpcClient)
	// Ideally we'd call ccip_router::get_state_address here, but we can't as the contract isn't deployed yet...
	routerStateAddress := ccipObjectAddress.ResourceAccount([]byte("CHAINLINK_CCIP_ROUTER"))
	evmFamilySelector, _ := hex.DecodeString("2812d52c")

	if err := addToProposal(ccipContract.RMNRemote().Encoder().Initialize(uint64(aptosChainSelector))); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().Initialize(big.NewInt(1000), linkTokenMetadataAddress, 12400, []aptos.AccountAddress{linkTokenMetadataAddress})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(onrampContract.Onramp().Encoder().Initialize(uint64(aptosChainSelector), deployer.AccountAddress(), deployer.AccountAddress(), []uint64{destChainSelector}, []aptos.AccountAddress{routerStateAddress}, []bool{false})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(onrampContract.Onramp().Encoder().ApplyDestChainConfigUpdatesV2([]uint64{destChainSelector}, []aptos.AccountAddress{ccipObjectAddress}, []aptos.AccountAddress{routerStateAddress}, []bool{false})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(routerContract.Router().Encoder().SetOnRampVersions([]uint64{destChainSelector}, [][]byte{{1, 6, 0}})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().ApplyFeeTokenUpdates(nil, []aptos.AccountAddress{linkTokenMetadataAddress})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().ApplyTokenTransferFeeConfigUpdates(destChainSelector, []aptos.AccountAddress{linkTokenMetadataAddress}, []uint32{1}, []uint32{10000}, []uint16{0}, []uint32{1000}, []uint32{1000}, []bool{true}, nil)); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().ApplyDestChainConfigUpdates(destChainSelector, true, 1, 10000, 7000000, 0, 0, 0, 0, 0, 0, 0, evmFamilySelector, false, 0, 0, 1000000, 0, 10000000, 0)); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().ApplyPremiumMultiplierWeiPerEthUpdates([]aptos.AccountAddress{linkTokenMetadataAddress}, []uint64{1})); err != nil {
		return CCIPDeployment{}, err
	}
	// To be able to call fee_quoter::update_prices, need to register as an allowed offramp
	if err := addToProposal(ccipContract.Auth().Encoder().ApplyAllowedOfframpUpdates(nil, []aptos.AccountAddress{ccipOwnerAddress})); err != nil {
		return CCIPDeployment{}, err
	}
	feeTokenPrice := big.NewInt(1).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().UpdatePrices([]aptos.AccountAddress{linkTokenMetadataAddress}, []*big.Int{feeTokenPrice}, []uint64{destChainSelector}, []*big.Int{big.NewInt(0)})); err != nil {
		return CCIPDeployment{}, err
	}

	// Deploy token pool to a separate object
	// Deploy LINK token
	tokenPoolSeed := "LINK_TOKEN_POOL"
	tokenPoolObjectAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectAddress(nil, []byte(tokenPoolSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object address for seed %v: %w", tokenPoolSeed, err)
	}
	lggr.Infof("Deploying Token Pool token to: %v", tokenPoolObjectAddress.StringLong())
	tokenPoolOwnerAddress, err := mcmsContract.MCMSRegistry().GetNewCodeObjectOwnerAddress(nil, []byte(tokenPoolSeed))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get new code object owner address for seed %v: %w", tokenPoolSeed, err)
	}
	lggr.Debugf("Token Pool owner address: %v", tokenPoolOwnerAddress.StringLong())

	// Deploy token pool to a new object
	tokenPoolPayload, err := token_pool.Compile(tokenPoolObjectAddress, ccipObjectAddress, mcmsAddress)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile token pool: %w", err)
	}
	chunks, _ = bind.CreateChunks(tokenPoolPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndPublishToObject(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, []byte(tokenPoolSeed))); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}

	// Deploy ManagedTokenPool on top of link token
	managedTokenPoolPayload, err := managed_token_pool.Compile(tokenPoolObjectAddress, ccipObjectAddress, mcmsAddress, tokenPoolObjectAddress, linkTokenObjectAddress, true)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to compile managed token pool: %w", err)
	}
	chunks, _ = bind.CreateChunks(managedTokenPoolPayload, bind.ChunkSizeInBytes)
	for i, chunk := range chunks {
		if i == len(chunks)-1 {
			if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunkAndUpgradeObjectCode(chunk.Metadata, chunk.CodeIndices, chunk.Chunks, tokenPoolObjectAddress)); err != nil {
				return CCIPDeployment{}, err
			}
			break
		}
		if err := addToProposal(mcmsContract.MCMSDeployer().Encoder().StageCodeChunk(chunk.Metadata, chunk.CodeIndices, chunk.Chunks)); err != nil {
			return CCIPDeployment{}, err
		}
	}
	managedTokenPoolContract := managed_token_pool.Bind(tokenPoolObjectAddress, rpcClient)
	managedTokenPoolStoreAddress := tokenPoolObjectAddress.ResourceAccount([]byte("CcipManagedTokenPool"))
	lggr.Debugf("Deployed Managed Token Pool to: %v", tokenPoolObjectAddress.StringLong())
	lggr.Debugf("Store resource account address: %v", managedTokenPoolStoreAddress)
	if err := addToProposal(linkTokenContract.ManagedToken().Encoder().ApplyAllowedMinterUpdates(nil, []aptos.AccountAddress{managedTokenPoolStoreAddress})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(linkTokenContract.ManagedToken().Encoder().ApplyAllowedBurnerUpdates(nil, []aptos.AccountAddress{managedTokenPoolStoreAddress})); err != nil {
		return CCIPDeployment{}, err
	}

	// Set up CCIP
	if err := addToProposal(ccipContract.FeeQuoter().Encoder().ApplyDestChainConfigUpdates(
		destChainSelector,
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
		evmFamilySelector,
		false,
		25,
		90_000,
		200_000,
		11e8,
		0,
		10,
	)); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(managedTokenPoolContract.ManagedTokenPool().Encoder().ApplyChainUpdates(nil, []uint64{destChainSelector}, [][][]byte{{common.HexToAddress("0x1111111B536498Bcd6326722E5Fd22D8234F1c7C").Bytes()}}, [][]byte{common.LeftPadBytes(common.HexToAddress("0x222222aF075ef84856A4DF03555E9777b2d227f6").Bytes(), 32)})); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(managedTokenPoolContract.ManagedTokenPool().Encoder().SetChainRateLimiterConfig(destChainSelector, false, 0, 0, false, 0, 0)); err != nil {
		return CCIPDeployment{}, err
	}
	// Set Administrator and call set_pool
	if err := addToProposal(ccipContract.TokenAdminRegistry().Encoder().ProposeAdministrator(linkTokenMetadataAddress, ccipOwnerAddress)); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.TokenAdminRegistry().Encoder().AcceptAdminRole(linkTokenMetadataAddress)); err != nil {
		return CCIPDeployment{}, err
	}
	if err := addToProposal(ccipContract.TokenAdminRegistry().Encoder().SetPool(linkTokenMetadataAddress, tokenPoolObjectAddress)); err != nil {
		return CCIPDeployment{}, err
	}

	// Build, setRoot and execute proposal
	timelockProposal, err := proposalBuilder.Build()
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to build proposal: %w", err)
	}
	convertersMap := map[mcmstypes.ChainSelector]mcmssdk.TimelockConverter{
		aptosChainSelector: aptossdk.NewTimelockConverter(),
	}
	proposal, _, err := timelockProposal.Convert(ctx, convertersMap)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to convert timelock proposal: %w", err)
	}

	inspector := aptossdk.NewInspector(rpcClient, aptossdk.TimelockRoleBypasser)
	inspectorsMap := map[mcmstypes.ChainSelector]mcmssdk.Inspector{
		aptosChainSelector: inspector,
	}
	signable, err := mcmslib.NewSignable(&proposal, inspectorsMap)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to create signable from proposal: %w", err)
	}
	_, err = signable.SignAndAppend(mcmslib.NewPrivateKeySigner(signerKeys[0]))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to sign proposal with first signer: %w", err)
	}
	_, err = signable.SignAndAppend(mcmslib.NewPrivateKeySigner(signerKeys[1]))
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to sign proposal with second signer: %w", err)
	}

	encoders, err := proposal.GetEncoders()
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to get proposal encoders: %w", err)
	}
	aptosEncoder := encoders[aptosChainSelector].(*aptossdk.Encoder)
	executorsMap := map[mcmstypes.ChainSelector]mcmssdk.Executor{
		aptosChainSelector: aptossdk.NewExecutor(rpcClient, deployer, aptosEncoder, aptossdk.TimelockRoleBypasser),
	}
	executable, err := mcmslib.NewExecutable(&proposal, executorsMap)
	if err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to create executable from proposal: %w", err)
	}

	lggr.Infof("⏳ Proposal built, starting execution...")
	// Set Root
	result, err = executable.SetRoot(ctx, aptosChainSelector)
	if err := waitForTransaction(err, &api.PendingTransaction{Hash: result.Hash}); err != nil {
		return CCIPDeployment{}, fmt.Errorf("failed to set root: %w", err)
	}
	lggr.Debugf("✅ Set root in tx %v", result.Hash)

	// Execute
	decoder := aptossdk.NewDecoder()
	for i, op := range proposal.Operations {
		// Decode operation
		decodedOp, err := decoder.Decode(op.Transaction, module_mcms.FunctionInfo)
		if err != nil {
			return CCIPDeployment{}, fmt.Errorf("failed to decode operation: %w", err)
		}
		method, args, err := decodedOp.String()
		_ = args
		if err != nil {
			return CCIPDeployment{}, fmt.Errorf("failed to convert decoded proposal to string: %w", err)
		}
		lggr.Debugf("Executing Operation %d (%v)\n", i, method)
		// lggr.Debugf(args)

		result, err = executable.Execute(ctx, i)
		if err := waitForTransaction(err, &api.PendingTransaction{Hash: result.Hash}); err != nil {
			return CCIPDeployment{}, fmt.Errorf("failed to execute operation: %w", err)
		}
	}
	lggr.Info("🚀 All executed successfully")

	return CCIPDeployment{
		MCMSAddress:      mcmsAddress,
		CCIPAddress:      ccipObjectAddress,
		LINKAddress:      linkTokenMetadataAddress,
		TokenPoolAddress: tokenPoolObjectAddress,
	}, nil
}

func SendMessageFromAptos(ctx context.Context, lggr logger.Logger, deployer *aptos.Account, rpcClient aptos.AptosRpcClient, deployment CCIPDeployment) (string, error) {
	opts := &bind.TransactOpts{Signer: deployer}

	toAddress := common.LeftPadBytes(common.HexToAddress("0x1234567890Be219c60A5940643A5cE7885223fC1").Bytes(), 32)

	extraArgs := MakeBCSEVMExtraArgsV2(big.NewInt(100), false)

	ccipRouterContract := ccip_router.Bind(deployment.CCIPAddress, rpcClient)
	fee, err := ccipRouterContract.Router().GetFee(nil, destChainSelector, toAddress, []byte("Hello, world!"), []aptos.AccountAddress{deployment.LINKAddress}, []uint64{1e8}, []aptos.AccountAddress{aptos.AccountZero}, deployment.LINKAddress, aptos.AccountZero, extraArgs)
	if err != nil {
		return "", fmt.Errorf("failed to get fee for message: %w", err)
	}
	lggr.Debugf("Estimated fee for message: %v", fee)

	tx, err := ccipRouterContract.Router().CCIPSend(opts, destChainSelector, toAddress, []byte("Hello, world!"), []aptos.AccountAddress{deployment.LINKAddress}, []uint64{1e8}, []aptos.AccountAddress{aptos.AccountZero}, deployment.LINKAddress, aptos.AccountZero, extraArgs)
	if err != nil {
		return "", fmt.Errorf("failed to encode ccip_send: %w", err)
	}
	data, err := rpcClient.WaitForTransaction(tx.Hash)
	if err != nil {
		return "", fmt.Errorf("failed to send ccip message: %w", err)
	}
	if !data.Success {
		return "", fmt.Errorf("transaction %v failed: %w", tx.Hash, data.VmStatus)
	}

	var eventsLog []any
	eventsLog = append(eventsLog, "tx", tx.Hash)
	for i, event := range data.Events {
		eventsLog = append(eventsLog, fmt.Sprintf("[%v]%v", i, event.Type), fmt.Sprintf("%+v", event.Data))
	}

	lggr.Infow("CCIP Message sent", eventsLog...)

	return tx.Hash, nil
}

const GenericExtraArgsV2Tag = "0x181dcf10"

// MakeBCSEVMExtraArgsV2 makes the BCS encoded extra args for a message sent from a Move based chain that is destined for an EVM chain.
// The extra args are used to specify the gas limit and allow out of order flag for the message.
func MakeBCSEVMExtraArgsV2(gasLimit *big.Int, allowOOO bool) []byte {
	s := &bcs.Serializer{}
	s.U256(*gasLimit)
	s.Bool(allowOOO)
	return append(hexutil.MustDecode(GenericExtraArgsV2Tag), s.ToBytes()...)
}
