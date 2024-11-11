#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

# deploy platform forwarder

PLATFORM_ADDR=$(cat platform/contract_address.txt)

aptos move upgrade-object-package \
  --package-dir platform \
  --object-address $PLATFORM_ADDR \
  --named-addresses platform=$PLATFORM_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
	--assume-yes
