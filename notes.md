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

Export a test key for local geth:
```
# openssl rand -hex 32
# NOTE: this is an example key from docs, DO NOT USE OUTSIDE OF DEVNET: https://web3js.readthedocs.io/en/v1.2.11/web3-eth-accounts.html#privatekeytoaccount
export ACCOUNT_KEY="348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
export ADDRESS="0xb8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01"
```

Switch to the `chainlink` repo:

`core/scripts/keystone`:

Add two node lists under `.cache`

(Ports from the node are forwarded so that host can talk to them if running in rootless containers to which DNS can't be resolved)

`NodeList.txt`
```
http://localhost:50100 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50101 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50102 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50103 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://localhost:50104 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
```

`NodeList.remote.txt`
```
http://chainlink.core.1:50100 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.2:50101 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.3:50102 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.4:50103 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
http://chainlink.core.5:50104 notreal@fakeemail.ch fj293fbBnlQ!f9vNs
```

Switch back to the `aptos` repository.

```
scripts/setup.sh
```

To remove workflows:

```
go run main.go delete-workflows
```

Then restart the core node, the workflows don't seem to shut down otherwise.


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
