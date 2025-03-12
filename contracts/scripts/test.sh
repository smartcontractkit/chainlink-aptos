#!/usr/bin/env bash
set -euxo pipefail

cd "$(dirname -- "$0")/.."

aptos move test --package-dir chainlink-common
aptos move test --package-dir platform
aptos move test --package-dir mcms/mcms
aptos move test --package-dir mcms/mcms_test
aptos move test --package-dir data-feeds

# CCIP
aptos move test --package-dir ccip/ccip
aptos move test --package-dir ccip/ccip_ping_pong_demo
aptos move test --package-dir ccip/ccip_router
aptos move test --package-dir ccip/ccip_token_pools/burn_mint_token_pool
aptos move test --package-dir ccip/ccip_token_pools/lock_release_token_pool
aptos move test --package-dir ccip/ccip_token_pools/token_pool
