#!/usr/bin/env bash
set -euxo pipefail

KEYSTONE_ADDR=$(cat keystone/contract_address.txt)

# forwarder::set_config
aptos move run --function-id "$KEYSTONE_ADDR::forwarder::set_config" --assume-yes --args u32:0 u32:0 u8:1 "hex:[$ORACLE_PUBKEYS]"
