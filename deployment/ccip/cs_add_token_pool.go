package ccip

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/smartcontractkit/mcms"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	aptosHelpers "github.com/smartcontractkit/chainlink-aptos/bindings/helpers"
	mcmsbind "github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/config"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	seq "github.com/smartcontractkit/chainlink-aptos/deployment/ccip/sequence"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/shared"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	"github.com/smartcontractkit/chainlink-aptos/deployment/stateview"

	"github.com/smartcontractkit/chainlink-deployments-framework/datastore"
	cldf "github.com/smartcontractkit/chainlink-deployments-framework/deployment"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
)

var _ cldf.ChangeSetV2[config.AddTokenPoolConfig] = AddTokenPool{}

// AddTokenPool deploys token pools and sets up tokens on lanes
type AddTokenPool struct{}

func (cs AddTokenPool) VerifyPreconditions(env cldf.Environment, cfg config.AddTokenPoolConfig) error {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}
	var errs []error
	// Validate supported chain
	supportedChains := state.SupportedChains()
	if _, ok := supportedChains[cfg.ChainSelector]; !ok {
		errs = append(errs, fmt.Errorf("unsupported chain: %d", cfg.ChainSelector))
	}
	// Validate CCIP deployed
	if state.AptosChains[cfg.ChainSelector].CCIPAddress == (aptos.AccountAddress{}) {
		errs = append(errs, fmt.Errorf("CCIP is not deployed on Aptos chain %d", cfg.ChainSelector))
	}
	// Validate MCMS config
	if cfg.MCMSConfig == nil {
		errs = append(errs, errors.New("MCMS config is required for AddTokenPool changeset"))
	}
	// Validate config.TokenParams. The token symbol is required in both paths because it is
	// the datastore qualifier for every ref this changeset records (see Qualifier()); the
	// remaining params only describe a token this changeset would deploy itself.
	if cfg.TokenCodeObjAddress == (aptos.AccountAddress{}) {
		err = cfg.TokenParams.Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid token parameters: %w", err))
		}
	} else {
		if cfg.Qualifier() == "" {
			errs = append(errs, errors.New("TokenParams.Symbol is required: it is the datastore qualifier for the token pool"))
		}
		if cfg.TokenAddress == (aptos.AccountAddress{}) {
			errs = append(errs, errors.New("TokenAddress must be provided when TokenCodeObjAddress is set"))
		}
		if err := verifyTokenSymbol(env, cfg, state); err != nil {
			errs = append(errs, err)
		}
	}
	// Validate config.EVMRemoteConfigs
	for chainSelector, remoteConfig := range cfg.EVMRemoteConfigs {
		if err := remoteConfig.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("invalid EVM remote config for chain %d: %w", chainSelector, err))
		}
	}
	// Validate that the datastore keys this changeset will write are free, before any
	// transaction is signed or staged.
	errs = append(errs, shared.ValidatePlannedRefs(env, cfg.ReplaceExisting, plannedTokenPoolRefs(cfg)))
	// Validate if token address is provided if pool address is specified
	if cfg.TokenCodeObjAddress == (aptos.AccountAddress{}) && cfg.TokenPoolAddress != (aptos.AccountAddress{}) {
		errs = append(errs, errors.New("token object address must be provided if token pool address is specified"))
	}
	// No token pool address provided, so no need to validate token address
	if cfg.TokenCodeObjAddress == (aptos.AccountAddress{}) && cfg.TokenPoolAddress == (aptos.AccountAddress{}) {
		return errors.Join(errs...)
	}
	// Validate if token already exists with different pool address
	for token, pool := range state.AptosChains[cfg.ChainSelector].AptosManagedTokenPools {
		if (token == cfg.TokenAddress) && (pool != cfg.TokenPoolAddress) {
			errs = append(errs, fmt.Errorf("token %s already exists with a different pool address %s", token.StringLong(), pool.StringLong()))
		}
		if (pool == cfg.TokenPoolAddress) && (token != cfg.TokenAddress) {
			errs = append(errs, fmt.Errorf("pool %s already exists with a different token address %s", pool.StringLong(), token.StringLong()))
		}
	}
	for token, pool := range state.AptosChains[cfg.ChainSelector].RegulatedTokenPools {
		if (token == cfg.TokenAddress) && (pool != cfg.TokenPoolAddress) {
			errs = append(errs, fmt.Errorf("token %s already exists with a different pool address %s", token.StringLong(), pool.StringLong()))
		}
		if (pool == cfg.TokenPoolAddress) && (token != cfg.TokenAddress) {
			errs = append(errs, fmt.Errorf("pool %s already exists with a different token address %s", pool.StringLong(), token.StringLong()))
		}
	}
	for token, pool := range state.AptosChains[cfg.ChainSelector].BurnMintTokenPools {
		if (token == cfg.TokenAddress) && (pool != cfg.TokenPoolAddress) {
			errs = append(errs, fmt.Errorf("token %s already exists with a different pool address %s", token.StringLong(), pool.StringLong()))
		}
		if (pool == cfg.TokenPoolAddress) && (token != cfg.TokenAddress) {
			errs = append(errs, fmt.Errorf("pool %s already exists with a different token address %s", pool.StringLong(), token.StringLong()))
		}
	}
	for token, pool := range state.AptosChains[cfg.ChainSelector].LockReleaseTokenPools {
		if (token == cfg.TokenAddress) && (pool != cfg.TokenPoolAddress) {
			errs = append(errs, fmt.Errorf("token %s already exists with a different pool address %s", token.StringLong(), pool.StringLong()))
		}
		if (pool == cfg.TokenPoolAddress) && (token != cfg.TokenAddress) {
			errs = append(errs, fmt.Errorf("pool %s already exists with a different token address %s", pool.StringLong(), token.StringLong()))
		}
	}
	// Validate regulated token ownership finalization preconditions: when adding a regulated
	// token pool against a pre-existing regulated token, a pending ownership transfer to MCMS
	// (if any) must be in a state where the deployer EOA can finalize it.
	if cfg.PoolType == shared.AptosRegulatedTokenPoolType && cfg.TokenCodeObjAddress != (aptos.AccountAddress{}) {
		deps := dependency.AptosDeps{
			AptosChain:       env.BlockChains.AptosChains()[cfg.ChainSelector],
			CCIPOnChainState: state,
		}
		mcmsAddress := state.AptosChains[cfg.ChainSelector].MCMSAddress
		if err := seq.VerifyFinalizeRegulatedTokenOwnership(deps, cfg.TokenCodeObjAddress, mcmsAddress); err != nil {
			errs = append(errs, fmt.Errorf("regulated token ownership finalize precondition: %w", err))
		}
	}
	return errors.Join(errs...)
}

// plannedTokenPoolRefs declares the datastore refs Apply will record, mirroring its
// conditionals: a caller-supplied token or pool address means that ref is not deployed here
// and therefore not planned. Every type this changeset records is token-scoped, so all of
// them are multi-instance and qualified by symbol.
func plannedTokenPoolRefs(cfg config.AddTokenPoolConfig) []shared.PlannedRef {
	qualifier := cfg.Qualifier().String()
	var refs []shared.PlannedRef
	if cfg.TokenCodeObjAddress == (aptos.AccountAddress{}) {
		refs = append(refs,
			shared.PlannedRef{
				ChainSelector: cfg.ChainSelector,
				Type:          shared.AptosManagedTokenType,
				Version:       Version1_6_0,
				Qualifier:     qualifier,
				MultiInstance: true,
			},
			shared.PlannedRef{
				ChainSelector: cfg.ChainSelector,
				Type:          cldf.ContractType(cfg.TokenParams.Symbol),
				Version:       Version1_6_0,
				Qualifier:     qualifier,
				MultiInstance: true,
			},
		)
	}
	if cfg.TokenPoolAddress == (aptos.AccountAddress{}) {
		refs = append(refs, shared.PlannedRef{
			ChainSelector: cfg.ChainSelector,
			Type:          cfg.PoolType,
			Version:       Version1_6_0,
			Qualifier:     qualifier,
			MultiInstance: true,
		})
	}

	return refs
}

// verifyTokenSymbol checks the configured token symbol against the symbol of the token the
// pool will serve, so a wrong qualifier cannot reach the datastore. Tokens this repo deployed
// are recorded by symbol in state (ManagedTokens is keyed by symbol); anything else is read on
// chain with the same helper the state loader uses. The comparison uses the raw configured
// symbol the datastore key is derived from it separately, normalized by TokenQualifier.
func verifyTokenSymbol(env cldf.Environment, cfg config.AddTokenPoolConfig, state stateview.CCIPOnChainState) error {
	if cfg.TokenParams.Symbol == "" || cfg.TokenAddress == (aptos.AccountAddress{}) {
		// Both are reported separately; nothing to compare against.
		return nil
	}
	for symbol, codeObjAddress := range state.AptosChains[cfg.ChainSelector].ManagedTokens {
		if codeObjAddress == cfg.TokenCodeObjAddress {
			if symbol != cfg.TokenParams.Symbol {
				return fmt.Errorf("TokenParams.Symbol %q does not match the recorded symbol %q of token object %s",
					cfg.TokenParams.Symbol, symbol, cfg.TokenCodeObjAddress.StringLong())
			}
			return nil
		}
	}
	aptosChain, ok := env.BlockChains.AptosChains()[cfg.ChainSelector]
	if !ok {
		// Unsupported chain is reported separately; there is no client to read the token with.
		return nil
	}
	metadata, err := aptosHelpers.GetFungibleAssetMetadata(aptosChain.Client, cfg.TokenAddress)
	if err != nil {
		return fmt.Errorf("failed to read fungible asset metadata for token %s: %w", cfg.TokenAddress.StringLong(), err)
	}
	if metadata.Symbol != cfg.TokenParams.Symbol.String() {
		return fmt.Errorf("TokenParams.Symbol %q does not match the on-chain symbol %q of token %s",
			cfg.TokenParams.Symbol, metadata.Symbol, cfg.TokenAddress.StringLong())
	}
	return nil
}

func (cs AddTokenPool) Apply(env cldf.Environment, cfg config.AddTokenPoolConfig) (cldf.ChangesetOutput, error) {
	state, err := stateview.LoadOnchainState(env)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to load Aptos onchain state: %w", err)
	}

	aptosChain := env.BlockChains.AptosChains()[cfg.ChainSelector]
	ab := cldf.NewMemoryAddressBook()
	ds := datastore.NewMemoryDataStore()
	seqReports := make([]operations.Report[any, any], 0)
	proposals := make([]mcms.TimelockProposal, 0)
	var mcmsOperations []mcmstypes.BatchOperation

	deps := dependency.AptosDeps{
		AB:               ab,
		AptosChain:       aptosChain,
		CCIPOnChainState: state,
	}

	// Finalize the regulated_token 3-step ownership handoff if needed: when MCMS has accepted
	// ownership but the original deployer hasn't called execute_ownership_transfer yet, the
	// token object still belongs to the deployer and isTokenOwnedByMCMS would return false.
	if cfg.PoolType == shared.AptosRegulatedTokenPoolType && cfg.TokenCodeObjAddress != (aptos.AccountAddress{}) {
		finalizeReport, err := operations.ExecuteSequence(
			env.OperationsBundle,
			seq.FinalizeRegulatedTokenOwnershipSequence,
			deps,
			cfg.TokenCodeObjAddress,
		)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to finalize regulated token ownership: %w", err)
		}
		seqReports = append(seqReports, finalizeReport.ExecutionReports...)
	}

	// Deploy Aptos Token
	tokenCodeObjAddress := cfg.TokenCodeObjAddress
	tokenAddress := cfg.TokenAddress
	if cfg.TokenCodeObjAddress == (aptos.AccountAddress{}) {
		deployTokenIn := seq.DeployTokenSeqInput{
			TokenParams: cfg.TokenParams,
			MCMSAddress: state.AptosChains[cfg.ChainSelector].MCMSAddress,
			TokenMint:   cfg.TokenMint,
		}
		deploySeq, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployAptosTokenSequence, deps, deployTokenIn)
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		tokenCodeObjAddress = deploySeq.Output.TokenCodeObjAddress
		tokenAddress = deploySeq.Output.TokenAddress
		seqReports = append(seqReports, deploySeq.ExecutionReports...)
		mcmsOperations = append(mcmsOperations, deploySeq.Output.MCMSOperations...)
		// Save token object address token-scoped, qualified by symbol
		typeAndVersion := cldf.NewTypeAndVersion(shared.AptosManagedTokenType, Version1_6_0)
		typeAndVersion.AddLabel(string(cfg.TokenParams.Symbol))
		if err := shared.RecordAddress(deps.AB, ds, cfg.ChainSelector, deploySeq.Output.TokenCodeObjAddress.StringLong(), typeAndVersion, cfg.Qualifier().String()); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to save token object address %s: %w", deploySeq.Output.TokenCodeObjAddress, err)
		}
		// Save token address — token-scoped, qualified by symbol
		typeAndVersion = cldf.NewTypeAndVersion(cldf.ContractType(cfg.TokenParams.Symbol), Version1_6_0)
		if err := shared.RecordAddress(deps.AB, ds, cfg.ChainSelector, deploySeq.Output.TokenAddress.StringLong(), typeAndVersion, cfg.Qualifier().String()); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to save token address %s: %w", deploySeq.Output.TokenAddress, err)
		}
	}

	// Deploy Aptos token pool
	tokenPoolAddress := cfg.TokenPoolAddress
	if cfg.TokenPoolAddress == (aptos.AccountAddress{}) {
		isOwned, err := isTokenOwnedByMCMS(deps, cfg.TokenCodeObjAddress)
		if err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to check if token is owned by MCMS: %w", err)
		}
		depInput := seq.DeployTokenPoolSeqInput{
			TokenCodeObjAddress: tokenCodeObjAddress,
			TokenAddress:        tokenAddress,
			PoolType:            cfg.PoolType,
			IsTokenOwnedByMCMS:  isOwned,
		}
		deploySeq, err := operations.ExecuteSequence(env.OperationsBundle, seq.DeployAptosTokenPoolSequence, deps, depInput)
		if err != nil {
			return cldf.ChangesetOutput{}, err
		}
		seqReports = append(seqReports, deploySeq.ExecutionReports...)
		mcmsOperations = append(mcmsOperations, deploySeq.Output.MCMSOps...)
		tokenPoolAddress = deploySeq.Output.TokenPoolAddress
		// Save token pool address token-scoped, qualified by symbol; the label keeps the
		// token address so the state loader can reconstruct the pool without RPC
		typeAndVersion := cldf.NewTypeAndVersion(cfg.PoolType, Version1_6_0)
		typeAndVersion.AddLabel(tokenAddress.StringLong())
		if err := shared.RecordAddress(deps.AB, ds, cfg.ChainSelector, deploySeq.Output.TokenPoolAddress.StringLong(), typeAndVersion, cfg.Qualifier().String()); err != nil {
			return cldf.ChangesetOutput{}, fmt.Errorf("failed to save token pool address %s: %w", deploySeq.Output.TokenPoolAddress, err)
		}
	}

	// Connect token pools EVM -> Aptos
	connInput := seq.ConnectTokenPoolSeqInput{
		TokenPoolAddress:                    tokenPoolAddress,
		TokenPoolType:                       cfg.PoolType,
		RemotePools:                         toRemotePools(cfg.EVMRemoteConfigs),
		TokenAddress:                        tokenAddress,
		TokenTransferFeeByRemoteChainConfig: cfg.TokenTransferFeeByRemoteChainConfig,
	}
	connectSeq, err := operations.ExecuteSequence(env.OperationsBundle, seq.ConnectTokenPoolSequence, deps, connInput)
	if err != nil {
		return cldf.ChangesetOutput{}, err
	}
	seqReports = append(seqReports, connectSeq.ExecutionReports...)
	mcmsOperations = append(mcmsOperations, connectSeq.Output)

	// Generate Aptos MCMS proposals
	proposal, err := utils.GenerateProposal(
		env,
		state.AptosChains[cfg.ChainSelector].MCMSAddress,
		cfg.ChainSelector,
		mcmsOperations,
		"Deploy and configure token pool on Aptos chain",
		*cfg.MCMSConfig,
	)
	if err != nil {
		return cldf.ChangesetOutput{}, fmt.Errorf("failed to generate MCMS proposal for Aptos chain %d: %w", cfg.ChainSelector, err)
	}
	proposals = append(proposals, *proposal)

	return cldf.ChangesetOutput{
		AddressBook:           ab,
		DataStore:             ds,
		MCMSTimelockProposals: proposals,
		Reports:               seqReports,
	}, nil
}

func isTokenOwnedByMCMS(deps dependency.AptosDeps, cfgTokenAddress aptos.AccountAddress) (bool, error) {
	if cfgTokenAddress == (aptos.AccountAddress{}) {
		// Token cfg not provided, so token is newly deployed and owned by MCMS
		return true, nil
	}
	mcmsAddress := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector].MCMSAddress
	mcmsContract := mcmsbind.Bind(mcmsAddress, deps.AptosChain.Client)
	isOwned, err := mcmsContract.MCMSRegistry().IsOwnedCodeObject(nil, cfgTokenAddress)
	if err != nil {
		eMsg := err.Error()
		if strings.Contains(eMsg, "E_ADDRESS_NOT_REGISTERED") {
			// If token is not registered, treat as just not owned by MCMS
			// This is not an error per se
			return false, nil
		}
		return false, fmt.Errorf("failed to check if token is owned by MCMS: %w", err)
	}
	return isOwned, nil
}

func toRemotePools(evmRemoteCfg map[uint64]config.EVMRemoteConfig) map[uint64]seq.RemotePool {
	remotePools := make(map[uint64]seq.RemotePool)
	for chainSelector, remoteConfig := range evmRemoteCfg {
		remotePools[chainSelector] = seq.RemotePool{
			RemotePoolAddress:  remoteConfig.TokenPoolAddress.Bytes(),
			RemoteTokenAddress: common.LeftPadBytes(remoteConfig.TokenAddress.Bytes(), 32),
			RateLimiterConfig:  remoteConfig.RateLimiterConfig,
		}
	}
	return remotePools
}
