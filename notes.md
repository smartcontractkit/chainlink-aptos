# Local development setup

Aptos scripts require `aptos` CLI, `jq` and `curl`.

Create a shared network for the containers
```
docker network create chainlink
```

Build a core image with plugins (OCR3 capability) and the aptos relayer
```
scripts/build.sh
```

Start up Postgres, local Geth network, Aptos local devnet, core nodes
```
scripts/postgres.sh
scripts/geth.sh
scripts/devnet.sh
scripts/core.sh
```

`contracts/`

Publish Aptos modules

```
aptos init --network local --assume-yes
scripts/publish.sh
```

Deploy feed `0x1111111111111111111100000000000000000000000000000000000000000000`

```
scripts/deploy.sh
```

Switch to the `chainlink` repo:

`core/scripts/keystone`:

Add two node lists under `.cache`

(Ports from the node are forwarded so that host can talk to them if running in rootless containers to which DNS can't be resolved)

`NodeList.local.txt`
```
http://localhost:50100 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50101 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50102 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50103 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50104 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
```

`NodeList.txt`
```
http://chainlink.core.1:50100 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.2:50101 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.3:50102 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.4:50103 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.5:50104 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
```

Remove any old `artifacts/` and `.cache/PublicKeys.json`

Add a test key and fund it
```
# openssl rand -hex 32
# NOTE: this is an example key from docs, DO NOT USE OUTSIDE OF DEVNET: https://web3js.readthedocs.io/en/v1.2.11/web3-eth-accounts.html#privatekeytoaccount
export ACCOUNT_KEY="348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
export ADDRESS="0xb8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01"


# (requires local geth CLI)
geth attach --exec "eth.sendTransaction({from: eth.accounts[0], to: '$ADDRESS', value: 20000000000000000000000})" http://127.0.0.1:8544
```

Deploy keystone contracts, OCR3 capability jobspecs and the test Aptos workflow

```
go run main.go deploy-contracts --ocrfile=ocr_config.json --chainid=1337 --ethurl=http://localhost:8544 --accountkey=$ACCOUNT_KEY

go run main.go deploy-jobspecs --chainid=1337 --p2pport=6691 --onlyreplay=false

go run main.go deploy-workflows --workflow=../../../../chainlink-internal-integrations/aptos/scripts/workflow.toml
```

To remove workflows:

```
go run main.go delete-workflows
```

Then restart the core node, the workflows don't seem to shut down otherwise.

Switch back to the `aptos` repository.

`contracts/`

Fund all the nodes

```
export ORACLE_ACCOUNTS=$(cat ../../../chainlink/core/scripts/keystone/.cache/PublicKeys.json | jq -r '.[].AptosAccount')
echo $ORACLE_ACCOUNTS | xargs -L1 aptos account fund-with-faucet --account
```

Configure the keystone forwarder to accept reports from the nodes

```
export ORACLE_PUBKEYS=$(cat ../../../chainlink/core/scripts/keystone/.cache/PublicKeys.json | jq '.[].AptosOnchainPublicKey' | paste -sd ",")
scripts/set_config.sh
```

TODO: need to edit core.sh with transmitter key

# Tips

Access `chainlink` CLI directly in a container of a node

```
podman exec chainlink.core.1 chainlink admin login -f /tmp/api_credentials --bypass-version-check
```

# TODO

- TODO: workflow target address needs to use deployed contract address
- make contract address files sourceable, use them to source address data for core node
- restart core nodes with proper addresses

TODO: can't compute transmission_id, since offchain it's the receiver module address, but onchain that could be manipulated
the solution would be that each receiver needs to register it's own resource_account that would be bound to it's own addr
