package operation

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	mcmstypes "github.com/smartcontractkit/mcms/types"

	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/dependency"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/utils"
	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/v1_6"
)

var OnRampOperations = []*operations.Operation[any, any, any]{
	ApplyOnRampDestChainConfigUpdatesV1Op.AsUntypedRelaxed(),
	UpdateOnRampDestsOp.AsUntypedRelaxed(),
	MigrateOnRampDestChainConfigsToV2Op.AsUntypedRelaxed(),
}

// ApplyOnRampDestChainConfigUpdatesV1Input configures legacy V1 OnRamp destination chain entries.
type ApplyOnRampDestChainConfigUpdatesV1Input struct {
	DestChainSelectors        []uint64
	DestChainRouters          []aptos.AccountAddress
	DestChainAllowlistEnabled []bool
}

// ApplyOnRampDestChainConfigUpdatesV1Op applies V1 OnRamp destination chain configs.
var ApplyOnRampDestChainConfigUpdatesV1Op = operations.NewOperation(
	"apply-onramp-dest-chain-config-updates-v1-op",
	Version1_0_0,
	"Applies legacy V1 OnRamp destination chain configurations",
	applyOnRampDestChainConfigUpdatesV1,
)

func applyOnRampDestChainConfigUpdatesV1(b operations.Bundle, deps dependency.AptosDeps, in ApplyOnRampDestChainConfigUpdatesV1Input) ([]mcmstypes.Transaction, error) {
	if len(in.DestChainSelectors) == 0 {
		return nil, nil
	}

	aptosState := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector]
	onrampBind := ccip_onramp.Bind(aptosState.CCIPAddress, deps.AptosChain.Client)

	moduleInfo, function, _, args, err := onrampBind.Onramp().Encoder().ApplyDestChainConfigUpdates(
		in.DestChainSelectors,
		in.DestChainRouters,
		in.DestChainAllowlistEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ApplyDestChainConfigUpdates for OnRamp: %w", err)
	}

	tx, err := utils.GenerateMCMSTx(aptosState.CCIPAddress, moduleInfo, function, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	return []mcmstypes.Transaction{tx}, nil
}

// UpdateOnRampDestsInput contains configuration for updating OnRamp destinations
type UpdateOnRampDestsInput struct {
	Updates map[uint64]v1_6.OnRampDestinationUpdate
}

// UpdateOnRampDestsOp operation to update OnRamp destination configurations
var UpdateOnRampDestsOp = operations.NewOperation(
	"update-onramp-dests-op",
	Version1_0_0,
	"Updates OnRamp destination chain configurations",
	updateOnRampDests,
)

func updateOnRampDests(b operations.Bundle, deps dependency.AptosDeps, in UpdateOnRampDestsInput) ([]mcmstypes.Transaction, error) {
	var txs []mcmstypes.Transaction

	aptosState := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector]
	// Bind CCIP Package
	ccipAddress := aptosState.CCIPAddress
	onrampBind := ccip_onramp.Bind(ccipAddress, deps.AptosChain.Client)

	// Transform the updates into the format expected by the Aptos contract
	var destChainSelectors []uint64
	var destChainRouters []aptos.AccountAddress
	var destChainRouterStateAddresses []aptos.AccountAddress
	var destChainAllowlistEnabled []bool

	// Get routers state addresses
	var testRouterStateAddress aptos.AccountAddress
	var routerStateAddress aptos.AccountAddress
	if aptosState.TestRouterAddress != (aptos.AccountAddress{}) {
		testRouter := ccip_router.Bind(aptosState.TestRouterAddress, deps.AptosChain.Client)
		stateAddress, err := testRouter.Router().GetStateAddress(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get test router state address: %w", err)
		}
		testRouterStateAddress = stateAddress
	}
	// Router address is the router module address
	router := ccip_router.Bind(ccipAddress, deps.AptosChain.Client)
	// Router state address is the router state signer address
	routerStateAddress, err := router.Router().GetStateAddress(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get router state address: %w", err)
	}

	// Process each destination chain config update
	for destChainSelector, update := range in.Updates {
		// destChainRouters and destChainRouterStateAddresses
		if !update.IsEnabled {
			destChainRouters = append(destChainRouters, aptos.AccountAddress{})
			destChainRouterStateAddresses = append(destChainRouterStateAddresses, aptos.AccountAddress{})
			continue
		}

		if update.TestRouter {
			destChainRouters = append(destChainRouters, aptosState.TestRouterAddress)
			destChainRouterStateAddresses = append(destChainRouterStateAddresses, testRouterStateAddress)
		} else {
			destChainRouters = append(destChainRouters, ccipAddress)
			destChainRouterStateAddresses = append(destChainRouterStateAddresses, routerStateAddress)
		}
		// destChainSelectors
		destChainSelectors = append(destChainSelectors, destChainSelector)
		// destChainAllowlistEnabled
		destChainAllowlistEnabled = append(destChainAllowlistEnabled, update.AllowListEnabled)
	}

	if len(destChainSelectors) == 0 {
		b.Logger.Infow("No OnRamp destination updates to apply")
		return nil, nil
	}

	// Encode the update operation
	moduleInfo, function, _, args, err := onrampBind.Onramp().Encoder().ApplyDestChainConfigUpdatesV2(
		destChainSelectors,
		destChainRouters,
		destChainRouterStateAddresses,
		destChainAllowlistEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ApplyDestChainConfigUpdates for OnRamp: %w", err)
	}
	tx, err := utils.GenerateMCMSTx(ccipAddress, moduleInfo, function, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}
	txs = append(txs, tx)

	b.Logger.Infow("Adding OnRamp destination config update operation",
		"chainCount", len(destChainSelectors))

	return txs, nil
}

type MigrateOnRampDestChainConfigsToV2Input struct {
	DestChainSelectors    []uint64
	RouterModuleAddresses []aptos.AccountAddress
}

var MigrateOnRampDestChainConfigsToV2Op = operations.NewOperation(
	"migrate-onramp-dest-chain-configs-to-v2-op",
	Version1_0_0,
	"Migrates OnRamp destination chain configs from V1 to V2",
	migrateOnRampDestChainConfigsToV2,
)

func migrateOnRampDestChainConfigsToV2(b operations.Bundle, deps dependency.AptosDeps, in MigrateOnRampDestChainConfigsToV2Input) ([]mcmstypes.Transaction, error) {
	aptosState := deps.CCIPOnChainState.AptosChains[deps.AptosChain.Selector]
	ccipAddress := aptosState.CCIPAddress
	onrampBind := ccip_onramp.Bind(ccipAddress, deps.AptosChain.Client)

	moduleInfo, function, _, args, err := onrampBind.Onramp().Encoder().MigrateDestChainConfigsToV2(
		in.DestChainSelectors,
		in.RouterModuleAddresses,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode MigrateDestChainConfigsToV2 for OnRamp: %w", err)
	}

	tx, err := utils.GenerateMCMSTx(ccipAddress, moduleInfo, function, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create transaction: %w", err)
	}

	b.Logger.Infow("Adding OnRamp migrate dest chain configs to V2 operation",
		"chainCount", len(in.DestChainSelectors))

	return []mcmstypes.Transaction{tx}, nil
}
