package contracts

import (
	"embed"
	"path/filepath"
)

//go:embed ccip large_packages mcms
var Embed embed.FS

type Package string

const (
	CCIP                = Package("ccip")
	CCIPPingPongDemo    = Package("ccip_ping_pong_demo")
	CCIPBurnMintPool    = Package("ccip_burn_mint_pool")
	CCIPLockReleasePool = Package("ccip_lock_release_pool")
	CCIPTokenPool       = Package("ccip_token_pool")
	CCIPRouter       	= Package("ccip_router")
	CCIPDummyReceiver = Package("ccip_dummy_receiver")

	MCMS     = Package("mcms")
	MCMSTest = Package("mcms_test")

	LargePackages = Package("large_packages")
)

// Contracts maps packages to their respective root directories within Embed
var Contracts map[Package]string = map[Package]string{
	CCIP:                filepath.Join("ccip", "ccip"),
	CCIPPingPongDemo:    filepath.Join("ccip", "ccip_ping_pong_demo"),
	CCIPBurnMintPool:    filepath.Join("ccip", "token_pools", "ccip_burn_mint_pool"),
	CCIPLockReleasePool: filepath.Join("ccip", "token_pools", "ccip_lock_release_pool"),
	CCIPTokenPool:       filepath.Join("ccip", "token_pools", "token_pool"),
	CCIPRouter:       	 filepath.Join("ccip", "ccip_router"),
	CCIPDummyReceiver:    filepath.Join("ccip", "ccip_dummy_receiver"),

	MCMS:     filepath.Join("mcms", "mcms"),
	MCMSTest: filepath.Join("mcms", "mcms_test"),

	LargePackages: "large_packages",
}
