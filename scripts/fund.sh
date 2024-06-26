#!/usr/bin/env bash

set -euo pipefail

container_basename="chainlink.core"

NODE_COUNT="${NODE_COUNT:-5}"

for ((i = 1; i <= NODE_COUNT; i++)); do
	container_name="${container_basename}.$i"
	echo "Funding ${container_name}"
	docker exec "${container_name}" chainlink admin login -f /tmp/api_credentials --bypass-version-check
	key=$(docker exec "${container_name}" chainlink keys eth list | grep Address | grep -Eo '0x[A-Fa-f0-9]+')
	geth attach --exec "eth.sendTransaction({from: eth.accounts[0], to: '$key', value: 20000000000000000000000})" http://127.0.0.1:8544
done
