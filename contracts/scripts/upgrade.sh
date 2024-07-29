#!/usr/bin/env bash
set -euxo pipefail

PUBLISHER_PROFILE=default
PUBLISHER_ADDR=0x$(aptos config show-profiles --profile=$PUBLISHER_PROFILE | grep 'account' | sed -n 's/.*"account": \"\(.*\)\".*/\1/p')

# deploy keystone forwarder

KEYSTONE_ADDR=$(cat keystone/contract_address.txt)

# TODO: make publisher also owner?
aptos move upgrade-object-package \
  --package-dir keystone \
  --object-address $KEYSTONE_ADDR \
  --named-addresses keystone=$KEYSTONE_ADDR,owner=$PUBLISHER_ADDR \
  --profile $PUBLISHER_PROFILE \
	--assume-yes
