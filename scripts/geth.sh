#!/usr/bin/env bash

set -euxo pipefail

bash "$(dirname -- "$0")/geth.down.sh"

container_name="chainlink.geth"
container_version="stable"

  # -d
docker run \
	-d \
	-p 127.0.0.1:8544:8544 \
  -p 127.0.0.1:8546:8546 \
	--name "${container_name}" \
	--network-alias "${container_name}" \
	--network chainlink \
  "ethereum/client-go:${container_version}" \
  --dev \
  --ipcdisable \
  --http \
  --http.vhosts '*' \
  --http.addr 0.0.0.0 \
 	--http.port=8544 \
  --ws \
  --ws.origins '*' \
  --ws.addr 0.0.0.0 \
	--ws.port=8546 \
  --allow-insecure-unlock \
  --rpc.allow-unprotected-txs \
  --http.corsdomain '*' \
  --vmdebug \
  --networkid 1337 \
  --dev.period 1 \
  --miner.gasprice 10

