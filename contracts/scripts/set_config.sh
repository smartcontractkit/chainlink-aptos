#!/usr/bin/env bash
set -euxo pipefail

PLATFORM_FORWARDER_ADDR=$(cat platform/contract_address.txt)

# forwarder::set_config
aptos move run --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::set_config" --assume-yes --args u32:1 u32:1 u8:1 "hex:[$ORACLE_PUBKEYS]"
