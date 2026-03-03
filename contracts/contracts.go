package contracts

import (
	"embed"
	"path/filepath"
)

//go:embed ccip large_packages mcms vendored data-feeds platform platform_secondary managed_token mcms_registrars managed_token_faucet regulated_token test_token
var Embed embed.FS

type Package string

const (
	CCIP                   = Package("ccip")
	CCIPPingPongDemo       = Package("ccip_ping_pong_demo")
	CCIPBurnMintPool       = Package("burn_mint_token_pool")
	CCIPLockReleasePool    = Package("lock_release_token_pool")
	CCIPRegulatedTokenPool = Package("regulated_token_pool")
	CCIPUSDCTokenPool      = Package("usdc_token_pool")
	CCIPManagedTokenPool   = Package("managed_token_pool")
	CCIPTokenPool          = Package("ccip_token_pool")
	CCIPRouter             = Package("ccip_router")
	CCIPDummyReceiver      = Package("ccip_dummy_receiver")
	CCIPOfframp            = Package("ccip_offramp")
	CCIPOnramp             = Package("ccip_onramp")

	ManagedToken       = Package("managed_token")
	RegulatedToken     = Package("regulated_token")
	ManagedTokenFaucet = Package("managed_token_faucet")

	ManagedTokenMCMSRegistrar   = Package("managed_token_mcms_registrar")
	RegulatedTokenMCMSRegistrar = Package("regulated_token_mcms_registrar")

	DataFeeds         = Package("data_feeds")
	Platform          = Package("platform")
	PlatformSecondary = Package("platform_secondary")

	MCMS      = Package("mcms")
	MCMSTest  = Package("mcms_test")
	CurseMCMS = Package("curse_mcms")

	LargePackages = Package("large_packages")

	TestToken             = Package("test_token")
	TestTokenBnMRegistrar = Package("bnm_registrar")
	TestTokenLnRRegistrar = Package("lnr_registrar")
)

// Contracts maps packages to their respective root directories within Embed
var Contracts map[Package]string = map[Package]string{
	CCIP:                   filepath.Join("ccip", "ccip"),
	CCIPPingPongDemo:       filepath.Join("ccip", "ccip_ping_pong_demo"),
	CCIPBurnMintPool:       filepath.Join("ccip", "ccip_token_pools", "burn_mint_token_pool"),
	CCIPLockReleasePool:    filepath.Join("ccip", "ccip_token_pools", "lock_release_token_pool"),
	CCIPRegulatedTokenPool: filepath.Join("ccip", "ccip_token_pools", "regulated_token_pool"),
	CCIPUSDCTokenPool:      filepath.Join("ccip", "ccip_token_pools", "usdc_token_pool"),
	CCIPManagedTokenPool:   filepath.Join("ccip", "ccip_token_pools", "managed_token_pool"),
	CCIPTokenPool:          filepath.Join("ccip", "ccip_token_pools", "token_pool"),
	CCIPRouter:             filepath.Join("ccip", "ccip_router"),
	CCIPDummyReceiver:      filepath.Join("ccip", "ccip_dummy_receiver"),
	CCIPOfframp:            filepath.Join("ccip", "ccip_offramp"),
	CCIPOnramp:             filepath.Join("ccip", "ccip_onramp"),
	DataFeeds:              "data-feeds",
	Platform:               "platform",
	PlatformSecondary:      "platform_secondary",

	ManagedToken:       filepath.Join("managed_token"),
	RegulatedToken:     filepath.Join("regulated_token"),
	ManagedTokenFaucet: filepath.Join("managed_token_faucet"),

	ManagedTokenMCMSRegistrar:   filepath.Join("mcms_registrars", "managed_token_mcms_registrar"),
	RegulatedTokenMCMSRegistrar: filepath.Join("mcms_registrars", "regulated_token_mcms_registrar"),

	MCMS:      filepath.Join("mcms", "mcms"),
	MCMSTest:  filepath.Join("mcms", "mcms_test"),
	CurseMCMS: filepath.Join("mcms", "curse_mcms"),

	LargePackages: "large_packages",

	TestToken:             filepath.Join("test_token", "test_token"),
	TestTokenBnMRegistrar: filepath.Join("test_token", "bnm_registrar"),
	TestTokenLnRRegistrar: filepath.Join("test_token", "lnr_registrar"),
}
