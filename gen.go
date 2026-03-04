package aptos

//go:generate go run ./cmd/bindgen --input ./contracts/managed_token/sources/allowlist.move --output ./bindings/managed_token/allowlist
//go:generate go run ./cmd/bindgen --input ./contracts/managed_token/sources/managed_token.move --output ./bindings/managed_token/managed_token
//go:generate go run ./cmd/bindgen --input ./contracts/managed_token/sources/ownable.move --output ./bindings/managed_token/ownable

//go:generate go run ./cmd/bindgen --input ./contracts/managed_token_faucet/sources/faucet.move --output ./bindings/managed_token_faucet/faucet

//go:generate go run ./cmd/bindgen --input ./contracts/regulated_token/sources/regulated_token.move --output ./bindings/regulated_token/regulated_token

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/auth.move --output ./bindings/ccip/auth
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/fee_quoter.move --output ./bindings/ccip/fee_quoter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/nonce_manager.move --output ./bindings/ccip/nonce_manager
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/receiver_registry.move --output ./bindings/ccip/receiver_registry
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/rmn_remote.move --output ./bindings/ccip/rmn_remote
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip/sources/token_admin_registry.move --output ./bindings/ccip/token_admin_registry

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_onramp/sources/onramp.move --output ./bindings/ccip_onramp/onramp
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_offramp/sources/offramp.move --output ./bindings/ccip_offramp/offramp --externalStructs ccip_offramp::ocr3_base::OCRConfig=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/ocr3_base
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_offramp/sources/ocr3_base.move --output ./bindings/ccip_offramp/ocr3_base

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_router/sources/router.move --output ./bindings/ccip_router/router
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_dummy_receiver/sources/dummy_receiver.move --output ./bindings/ccip_dummy_receiver/dummy_receiver
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_dummy_receiver/sources/ptt_dummy_receiver.move --output ./bindings/ccip_dummy_receiver/ptt_dummy_receiver

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/burn_mint_token_pool/sources/burn_mint_token_pool.move --output ./bindings/ccip_token_pools/burn_mint_token_pool/burn_mint_token_pool --externalStructs ccip_token_pool::rate_limiter::TokenBucket=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/lock_release_token_pool/sources/lock_release_token_pool.move --output ./bindings/ccip_token_pools/lock_release_token_pool/lock_release_token_pool --externalStructs ccip_token_pool::rate_limiter::TokenBucket=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/usdc_token_pool/sources/usdc_token_pool.move --output ./bindings/ccip_token_pools/usdc_token_pool/usdc_token_pool --externalStructs ccip_token_pool::rate_limiter::TokenBucket=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/managed_token_pool/sources/managed_token_pool.move --output ./bindings/ccip_token_pools/managed_token_pool/managed_token_pool --externalStructs ccip_token_pool::rate_limiter::TokenBucket=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/regulated_token_pool/sources/regulated_token_pool.move --output ./bindings/ccip_token_pools/regulated_token_pool/regulated_token_pool --externalStructs ccip_token_pool::rate_limiter::TokenBucket=github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/token_pool/rate_limiter

//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/rate_limiter.move --output ./bindings/ccip_token_pools/token_pool/rate_limiter
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/token_pool.move --output ./bindings/ccip_token_pools/token_pool/token_pool
//go:generate go run ./cmd/bindgen --input ./contracts/ccip/ccip_token_pools/token_pool/sources/token_pool_rate_limiter.move --output ./bindings/ccip_token_pools/token_pool/token_pool_rate_limiter

//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms.move --output ./bindings/mcms/mcms
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_account.move --output ./bindings/mcms/mcms_account
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_deployer.move --output ./bindings/mcms/mcms_deployer
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_executor.move --output ./bindings/mcms/mcms_executor
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms/sources/mcms_registry.move --output ./bindings/mcms/mcms_registry

//go:generate go run ./cmd/bindgen --input ./contracts/mcms/curse_mcms/sources/curse_mcms.move --output ./bindings/curse_mcms/curse_mcms
//go:generate go run ./cmd/bindgen --input ./contracts/mcms/curse_mcms/sources/curse_mcms_account.move --output ./bindings/curse_mcms/curse_mcms_account

//go:generate go run ./cmd/bindgen --input ./contracts/mcms/mcms_test/sources/mcms_user.move --output ./bindings/mcms_test/mcms_user

//go:generate go run ./cmd/bindgen --input ./contracts/data-feeds/sources/registry.move --output ./bindings/data_feeds/registry
//go:generate go run ./cmd/bindgen --input ./contracts/data-feeds/sources/router.move --output ./bindings/data_feeds/router

//go:generate go run ./cmd/bindgen --input ./contracts/platform/sources/forwarder.move --output ./bindings/platform/forwarder
//go:generate go run ./cmd/bindgen --input ./contracts/platform/sources/storage.move --output ./bindings/platform/storage

//go:generate go run ./cmd/bindgen --input ./contracts/platform_secondary/sources/forwarder.move --output ./bindings/platform_secondary/forwarder
//go:generate go run ./cmd/bindgen --input ./contracts/platform_secondary/sources/storage.move --output ./bindings/platform_secondary/storage

//go:generate go run ./cmd/bindgen --input ./contracts/test_token/test_token/sources/test_token.move --output ./bindings/test_token/test_token/test_token
//go:generate go run ./cmd/bindgen --input ./contracts/test_token/bnm_registrar/sources/bnm_registrar.move --output ./bindings/test_token/bnm_registrar/bnm_registrar
//go:generate go run ./cmd/bindgen --input ./contracts/test_token/lnr_registrar/sources/lnr_registrar.move --output ./bindings/test_token/lnr_registrar/lnr_registrar
