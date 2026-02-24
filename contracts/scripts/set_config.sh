#!/usr/bin/env bash
set -euxo pipefail

# Use PLATFORM_FORWARDER_ADDR from env or from platform/contract_address.txt (after publish.sh).
# Use PUBLISHER_PROFILE from env for devnet (e.g. PUBLISHER_PROFILE=devnet).
PLATFORM_FORWARDER_ADDR=${PLATFORM_FORWARDER_ADDR:-$(cat platform/contract_address.txt)}
PUBLISHER_PROFILE=${PUBLISHER_PROFILE:-default}

if [ -z "$ORACLE_PUBKEYS" ]; then
  echo "ORACLE_PUBKEYS is required (comma-separated quoted hex keys, e.g. \"0xabc\",\"0xdef\")"
  exit 1
fi

# forwarder::set_config(don_id, config_version, f, oracles)
aptos move run --function-id "$PLATFORM_FORWARDER_ADDR::forwarder::set_config" --profile "$PUBLISHER_PROFILE" --assume-yes --args u32:1 u32:1 u8:1 "hex:[$ORACLE_PUBKEYS]"
