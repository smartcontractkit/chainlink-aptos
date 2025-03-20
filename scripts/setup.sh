#!/usr/bin/env bash

set -euxo pipefail

pushd "$(dirname -- "$0")/.."

bash "scripts/postgres.sh"
bash "scripts/geth.sh"
bash "scripts/devnet.sh"

pushd "contracts"

aptos init --network local --assume-yes
bash "scripts/publish.sh"
bash "scripts/deploy.sh"

popd

bash "scripts/core.sh"

keystone_dir="$(realpath ../../chainlink/core/scripts/keystone)"
pushd "$keystone_dir"


# Fund deployment key
geth attach --exec "eth.sendTransaction({from: eth.accounts[0], to: '$ADDRESS', value: 20000000000000000000000})" http://127.0.0.1:8544

go run main.go toolkit deploy-ocr3-contracts \
  --ethurl=http://localhost:8544 \
  --accountkey=$ACCOUNT_KEY \
  --chainid=1337 \
  --ocrfile=ocr_config.json

go run main.go toolkit get-aptos-keys \
  --chainid=1337
popd

pushd "contracts"

pubnodekeyspath="$keystone_dir/artefacts/pubnodekeys.json"

export ORACLE_ACCOUNTS=$(cat "$pubnodekeyspath" | jq -r '.[].AptosAccount')
echo "$ORACLE_ACCOUNTS" | xargs -L1 aptos account fund-with-faucet --account

export ORACLE_PUBKEYS=$(cat "$pubnodekeyspath" | jq '.[].AptosOnchainPublicKey' | paste -sd ",")
scripts/set_config.sh

popd

pushd "$keystone_dir"

go run main.go toolkit deploy-ocr3-jobspecs \
  --ethurl=http://localhost:8544 \
  --accountkey=$ACCOUNT_KEY \
  --chainid=1337 \
  --p2pport=6691

go run main.go toolkit deploy-workflows \
  --workflow=../../../../chainlink-aptos/scripts/workflow.toml
popd

# docker logs -f chainlink.core.2 | rg -F '"Hash"'
