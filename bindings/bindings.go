package bindings

import (
	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_dummy_receiver"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_onramp"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_router"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/burn_mint_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/managed_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/regulated_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/usdc_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/curse_mcms"
	"github.com/smartcontractkit/chainlink-aptos/bindings/data_feeds"
	"github.com/smartcontractkit/chainlink-aptos/bindings/managed_token"
	"github.com/smartcontractkit/chainlink-aptos/bindings/managed_token_faucet"
	"github.com/smartcontractkit/chainlink-aptos/bindings/mcms"
	mcmstest "github.com/smartcontractkit/chainlink-aptos/bindings/mcms_test"
	"github.com/smartcontractkit/chainlink-aptos/bindings/platform"
	"github.com/smartcontractkit/chainlink-aptos/bindings/regulated_token"
	"github.com/smartcontractkit/chainlink-aptos/bindings/test_token/bnm_registrar"
	"github.com/smartcontractkit/chainlink-aptos/bindings/test_token/lnr_registrar"
	"github.com/smartcontractkit/chainlink-aptos/bindings/test_token/test_token"
)

var GlobalFunctionInfo = bind.CombineFunctionInfos(
	ccip.FunctionInfo,
	ccip_dummy_receiver.FunctionInfo,
	ccip_offramp.FunctionInfo,
	ccip_onramp.FunctionInfo,
	ccip_router.FunctionInfo,
	burn_mint_token_pool.FunctionInfo,
	lock_release_token_pool.FunctionInfo,
	managed_token_pool.FunctionInfo,
	token_pool.FunctionInfo,
	usdc_token_pool.FunctionInfo,
	curse_mcms.FunctionInfo,
	data_feeds.FunctionInfo,
	managed_token.FunctionInfo,
	managed_token_faucet.FunctionInfo,
	mcms.FunctionInfo,
	mcmstest.FunctionInfo,
	platform.FunctionInfo,
	regulated_token.FunctionInfo,
	regulated_token_pool.FunctionInfo,
	test_token.FunctionInfo,
	bnm_registrar.FunctionInfo,
	lnr_registrar.FunctionInfo,
)

// package -> module -> function name
var globalRegistry = make(map[string]map[string]map[string]bind.FunctionInfo)

func init() {
	RegisterWithGlobalRegistry(GlobalFunctionInfo...)
}

func RegisterWithGlobalRegistry(functionInfos ...bind.FunctionInfo) {
	for _, info := range functionInfos {
		packageRegistry := globalRegistry[info.Package]
		if packageRegistry == nil {
			globalRegistry[info.Package] = make(map[string]map[string]bind.FunctionInfo)
		}
		moduleRegistry := globalRegistry[info.Package][info.Module]
		if moduleRegistry == nil {
			globalRegistry[info.Package][info.Module] = make(map[string]bind.FunctionInfo)
		}
		globalRegistry[info.Package][info.Module][info.Name] = info
	}
}

func GetFunctionInfo(packageModuleFunction ...string) bind.FunctionInfos {
	var infos []bind.FunctionInfo
	switch len(packageModuleFunction) {
	case 0:
		for _, v := range globalRegistry {
			for _, vv := range v {
				for _, info := range vv {
					infos = append(infos, info)
				}
			}
		}
	case 1:
		for _, v := range globalRegistry[packageModuleFunction[0]] {
			for _, info := range v {
				infos = append(infos, info)
			}
		}
	case 2:
		for _, info := range globalRegistry[packageModuleFunction[0]][packageModuleFunction[1]] {
			infos = append(infos, info)
		}
	case 3:
		infos = append(infos, globalRegistry[packageModuleFunction[0]][packageModuleFunction[1]][packageModuleFunction[2]])
	default:
		return nil
	}

	return infos
}
