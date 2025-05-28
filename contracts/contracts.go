package contracts

import (
	"embed"
	"path/filepath"
)

//go:embed ccip large_packages mcms vendored data-feeds platform platform_secondary managed_token mcms-registrar
var Embed embed.FS

type Package string

const (
	CCIP                 = Package("ccip")
	CCIPPingPongDemo     = Package("ccip_ping_pong_demo")
	CCIPBurnMintPool     = Package("burn_mint_token_pool")
	CCIPLockReleasePool  = Package("lock_release_token_pool")
	CCIPUSDCTokenPool    = Package("usdc_token_pool")
	CCIPManagedTokenPool = Package("managed_token_pool")
	CCIPTokenPool        = Package("ccip_token_pool")
	CCIPRouter           = Package("ccip_router")
	CCIPDummyReceiver    = Package("ccip_dummy_receiver")
	CCIPOfframp          = Package("ccip_offramp")
	CCIPOnramp           = Package("ccip_onramp")

	ManagedToken  = Package("managed_token")
	MCMSRegistrar = Package("mcms-registrar")

	DataFeeds         = Package("data_feeds")
	Platform          = Package("platform")
	PlatformSecondary = Package("platform_secondary")

	MCMS     = Package("mcms")
	MCMSTest = Package("mcms_test")

	LargePackages = Package("large_packages")
)

// Contracts maps packages to their respective root directories within Embed
var Contracts map[Package]string = map[Package]string{
	CCIP:                 filepath.Join("ccip", "ccip"),
	CCIPPingPongDemo:     filepath.Join("ccip", "ccip_ping_pong_demo"),
	CCIPBurnMintPool:     filepath.Join("ccip", "ccip_token_pools", "burn_mint_token_pool"),
	CCIPLockReleasePool:  filepath.Join("ccip", "ccip_token_pools", "lock_release_token_pool"),
	CCIPUSDCTokenPool:    filepath.Join("ccip", "ccip_token_pools", "usdc_token_pool"),
	CCIPManagedTokenPool: filepath.Join("ccip", "ccip_token_pools", "managed_token_pool"),
	CCIPTokenPool:        filepath.Join("ccip", "ccip_token_pools", "token_pool"),
	CCIPRouter:           filepath.Join("ccip", "ccip_router"),
	CCIPDummyReceiver:    filepath.Join("ccip", "ccip_dummy_receiver"),
	CCIPOfframp:          filepath.Join("ccip", "ccip_offramp"),
	CCIPOnramp:           filepath.Join("ccip", "ccip_onramp"),
	DataFeeds:            "data-feeds",
	Platform:             "platform",
	PlatformSecondary:    "platform_secondary",

	ManagedToken:  filepath.Join("managed_token"),
	MCMSRegistrar: filepath.Join("mcms-registrar"),

	MCMS:     filepath.Join("mcms", "mcms"),
	MCMSTest: filepath.Join("mcms", "mcms_test"),

	LargePackages: "large_packages",
}
