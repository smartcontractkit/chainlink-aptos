#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

# deploy platform forwarder

OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir platform \
  --address-name platform \
  --named-addresses platform=$PUBLISHER_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
	--assume-yes)
 
# # Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > platform/contract_address.txt
PLATFORM_FORWARDER_ADDR=$(cat platform/contract_address.txt)
echo "Contract deployed to address: $PLATFORM_FORWARDER_ADDR"
echo "Contract address saved to contract_address.txt"

# deploy data feeds

 OUTPUT=$(aptos move create-object-and-publish-package \
  --package-dir data-feeds \
  --address-name data_feeds \
  --named-addresses data_feeds=$PUBLISHER_ADDR,platform=$PLATFORM_FORWARDER_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
 --assume-yes)

# Extract the deployed contract address and save it to a file
echo "$OUTPUT" | grep "Code was successfully deployed to object address" | awk '{print $NF}' | sed 's/\.$//' > data-feeds/contract_address.txt
DATA_FEEDS_ADDR=$(cat data-feeds/contract_address.txt)
echo "Contract deployed to address: $DATA_FEEDS_ADDR"
echo "Contract address saved to contract_address.txt"
