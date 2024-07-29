#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

KEYSTONE_ADDR=$(cat keystone/contract_address.txt)
DATA_FEEDS_ADDR=$(cat data-feeds/contract_address.txt)

# data_feeds::router::set_feed_configs(config_ids, deviation_thresholds, staleness_seconds)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feed_configs" --assume-yes --args 'hex:["0x99"]' 'u256:[1]' 'u256:[60]'

# data_feeds::router::set_feeds(feed_ids, descriptions, config_id)
aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" --assume-yes --args 'hex:["0x0003111111111111111100000000000000000000000000000000000000000000"]' 'string:["FOOBAR"]' 'hex:0x99'

aptos move run --function-id "$DATA_FEEDS_ADDR::registry::set_feeds" --assume-yes --args 'hex:["0x0003222222222222222200000000000000000000000000000000000000000000"]' 'string:["BARFOO"]' 'hex:0x99'

# data_feeds::router::get_benchmarks(feed_ids, billing_data)
