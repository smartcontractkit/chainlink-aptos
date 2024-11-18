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

pushd "../../chainlink/core/scripts/keystone"


# Fund deployment key
geth attach --exec "eth.sendTransaction({from: eth.accounts[0], to: '$ADDRESS', value: 20000000000000000000000})" http://127.0.0.1:8544

go run main.go toolkit deploy-ocr3-and-forwarder-contracts \
  --ethurl=http://localhost:8544 \
  --accountkey=$ACCOUNT_KEY \
  --chainid=1337 \
  --ocrfile=ocr_config.json 

popd

pushd "contracts"

export ORACLE_ACCOUNTS=$(cat ../../../chainlink/core/scripts/keystone/.cache/PublicKeys.json | jq -r '.[].AptosAccount')
echo "$ORACLE_ACCOUNTS" | xargs -L1 aptos account fund-with-faucet --account

export ORACLE_PUBKEYS=$(cat ../../../chainlink/core/scripts/keystone/.cache/PublicKeys.json | jq '.[].AptosOnchainPublicKey' | paste -sd ",")
scripts/set_config.sh

popd

pushd "../../chainlink/core/scripts/keystone"

go run main.go toolkit deploy-ocr3-jobspecs \
  --ethurl=http://localhost:8544 \
  --accountkey=$ACCOUNT_KEY \
  --chainid=1337

go run main.go toolkit deploy-workflows \
  --workflow=../../../../chainlink-internal-integrations/aptos/scripts/workflow.toml

# docker logs -f chainlink.core.2 | rg -F '"Hash"'
