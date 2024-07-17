#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

KEYSTONE_ADDR=$(cat keystone/contract_address.txt)
DATA_FEEDS_ADDR=$(cat data-feeds/contract_address.txt)

# data_feeds::router::initialize(owner)
OUTPUT=$(aptos move run --function-id "$DATA_FEEDS_ADDR::router::initialize" --assume-yes --args address:$PUBLISHER_ADDR)
# parse out router addr
# TODO: is there really no better way?
TX=$(echo "$OUTPUT" | jq -r '.Result.transaction_hash')
ROUTER_ADDR=$(curl http://127.0.0.1:8080/v1/transactions/by_hash/$TX | jq -r '.events[] | select(.type | contains("router::Initialized")) | .data.address')

# data_feeds::registry::initialize(owner, router)
OUTPUT=$(aptos move run --function-id "$DATA_FEEDS_ADDR::registry::initialize" --assume-yes --args address:$PUBLISHER_ADDR address:$ROUTER_ADDR)
# parse out registry addr
TX=$(echo "$OUTPUT" | jq -r '.Result.transaction_hash')
REGISTRY_ADDR=$(curl http://127.0.0.1:8080/v1/transactions/by_hash/$TX | jq -r '.events[] | select(.type | contains("registry::Initialized")) | .data.address')

# data_feeds::router::set_feed_configs(registry, config_ids, deviation_thresholds, staleness_seconds)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feed_configs" --assume-yes --args address:$REGISTRY_ADDR 'hex:["0x99"]' 'u256:[1]' 'u256:[60]'

# data_feeds::router::set_feeds(registry, feed_ids, descriptions, config_id, upkeep) # TODO: upkeep 0x1 for now (0x1 could maybe be circumvented?)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" --assume-yes --args address:$REGISTRY_ADDR 'hex:["0x1111111111111111111100000000000000000000000000000000000000000000"]' 'string:["ETCBTH"]' 'hex:0x99' 'address:0x1'

# data_feeds::router::get_benchmarks(router, feed_ids, billing_data)
