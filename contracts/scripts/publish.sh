#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

# deploy keystone forwarder

# TODO: make publisher also owner?
OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir keystone \
  --address-name keystone \
  --named-addresses keystone=$PUBLISHER_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
	--assume-yes)
 
# # Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > keystone/contract_address.txt
KEYSTONE_ADDR=$(cat keystone/contract_address.txt)
echo "Contract deployed to address: $KEYSTONE_ADDR"
echo "Contract address saved to contract_address.txt"

# TODO: initialize ed25519 ocr2 signing key on all nodes, fetch pubkeys and pass them into set_config 

# forwarder::set_config
aptos move run --function-id "$KEYSTONE_ADDR::forwarder::set_config" --assume-yes --args u32:0 u32:0 u8:1 'hex:["0x0000000000000000000000000000000000000000000000000000000000000000"]'

# deploy data feeds

 OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir data-feeds \
  --address-name data_feeds \
  --named-addresses data_feeds=$PUBLISHER_ADDR,keystone=$KEYSTONE_ADDR \
  --profile $PUBLISHER_PROFILE \
 --assume-yes)

# Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > data-feeds/contract_address.txt
DATA_FEEDS_ADDR=$(cat data-feeds/contract_address.txt)
echo "Contract deployed to address: $DATA_FEEDS_ADDR"
echo "Contract address saved to contract_address.txt"

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
