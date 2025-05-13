package aptos

//go:generate go run ./cmd/bindgen --input ./contracts/link-token/sources/allowlist.move --output ./bindings/link-token/allowlist
// //go:generate go run ./cmd/bindgen --input ./contracts/link-token/sources/link_token.move --output ./bindings/link-token/link_token
//go:generate go run ./cmd/bindgen --input ./contracts/link-token/sources/ownable.move --output ./bindings/link-token/ownable

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/auth.move --output ./bindings/ccip/auth
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/fee_quoter.move --output ./bindings/ccip/fee_quoter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/receiver_registry.move --output ./bindings/ccip/receiver_registry
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/rmn_remote.move --output ./bindings/ccip/rmn_remote
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/token_admin_registry.move --output ./bindings/ccip/token_admin_registry

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_onramp/sources/onramp.move --output ./bindings/ccip_onramp/onramp
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_offramp/sources/offramp.move --output ./bindings/ccip_offramp/offramp --externalStructs ccip_offramp::ocr3_base::OCRConfig=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/ocr3_base
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_offramp/sources/ocr3_base.move --output ./bindings/ccip_offramp/ocr3_base

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_router/sources/router.move --output ./bindings/ccip_router/router
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_dummy_receiver/sources/dummy_receiver.move --output ./bindings/ccip_dummy_receiver/dummy_receiver

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/burn_mint_token_pool/sources/burn_mint_token_pool.move --output ./bindings/ccip_token_pools/burn_mint_token_pool/burn_mint_token_pool
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/lock_release_token_pool/sources/lock_release_token_pool.move --output ./bindings/ccip_token_pools/lock_release_token_pool/lock_release_token_pool
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/usdc_token_pool/sources/usdc_token_pool.move --output ./bindings/ccip_token_pools/usdc_token_pool/usdc_token_pool

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/rate_limiter.move --output ./bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/token_pool.move --output ./bindings/ccip_token_pools/token_pool/token_pool
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/token_pool_rate_limiter.move --output ./bindings/ccip_token_pools/token_pool/token_pool_rate_limiter

//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms.move --output ./bindings/mcms/mcms
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_account.move --output ./bindings/mcms/mcms_account
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_deployer.move --output ./bindings/mcms/mcms_deployer
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_executor.move --output ./bindings/mcms/mcms_executor
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_registry.move --output ./bindings/mcms/mcms_registry

//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms_test/sources/mcms_user.move --output ./bindings/mcms_test/mcms_user

//go:generate go run ./cmd/bindgen --input ./contracts/data-feeds/sources/registry.move --output ./bindings/data_feeds/registry
//go:generate go run ./cmd/bindgen --input ./contracts/data-feeds/sources/router.move --output ./bindings/data_feeds/router

//go:generate go run ./cmd/bindgen --input ./contracts/platform/sources/forwarder.move --output ./bindings/platform/forwarder
//go:generate go run ./cmd/bindgen --input ./contracts/platform/sources/storage.move --output ./bindings/platform/storage
