# Developer enviroment

Aptos scripts require `go`, `docker`, `geth`, `aptos`, `jq`, and `curl` .

Enter the developer enviroment using Nix:

```bash
nix develop
```

## macOS

Notice:

- Aptos CLI is currently excluded from the Nix devshell for Mac (needs to get packaged), alternatively install manually via [homebrew](https://aptos.dev/en/build/cli/install-cli/install-cli-mac).
- Docker emulation via Rosetta might not work (e.g., "Illegal instruction" error for Aptos node container), alternatively use [default (slower) QEMU emulation](https://news.ycombinator.com/item?id=25449561) by disabling the "Use Rosetta for x86_64/amd64 emulation on Apple Silicon" Docker config.

# Getting started - local setup

Create a shared network for the containers

```bash
docker network create chainlink
```

Build a core image with plugins (OCR3 capability) and the aptos relayer

```bash
scripts/build.sh
```

Export a test key for local geth:

```bash
# openssl rand -hex 32
# NOTE: this is an example key from docs, DO NOT USE OUTSIDE OF DEVNET: https://web3js.readthedocs.io/en/v1.2.11/web3-eth-accounts.html#privatekeytoaccount
export ACCOUNT_KEY="348ce564d427a3311b6536bbcff9390d69395b06ed6c486954e971d960fe8709"
export ADDRESS="0xb8CE9ab6943e0eCED004cDe8e3bBed6568B2Fa01"
```

Switch to the `chainlink` repo:

`core/scripts/keystone`:

Add a node list file under `.cache`

(Ports from the node are forwarded so that host can talk to them if running in rootless containers to which DNS can't be resolved)

`NodeList.txt`

```
http://localhost:50100 notreal@fakeemail.ch fj293fbBnlQ!f9vNs http://chainlink.core.1:50100
http://localhost:50101 notreal@fakeemail.ch fj293fbBnlQ!f9vNs http://chainlink.core.2:50101
http://localhost:50102 notreal@fakeemail.ch fj293fbBnlQ!f9vNs http://chainlink.core.3:50102
http://localhost:50103 notreal@fakeemail.ch fj293fbBnlQ!f9vNs http://chainlink.core.4:50103
http://localhost:50104 notreal@fakeemail.ch fj293fbBnlQ!f9vNs http://chainlink.core.5:50104

```

Switch back to the `aptos` repository.

```bash
scripts/setup.sh
```

To remove workflows:

```bash
go run main.go delete-workflows
```

Then restart the core node, the workflows don't seem to shut down otherwise.

# Tips

Access `chainlink` CLI directly in a container of a node

```bash
podman exec chainlink.core.1 chainlink admin login -f /tmp/api_credentials --bypass-version-check
```

Inspect round:

```bash
curl http://127.0.0.1:8080/v1/transactions/by_hash/0xe69848c6fe69b57b4feb763e720db12ea16dd214d8007995090a18ca52a82bb4 | jq '.events[] | select(.type | contains("FeedUpdated"))'
```

# Protobuf

We use protobuf to define monitoring messages types.

Lint `.proto` files using:

```bash
protolint lint --fix .
```

To generate Go type bindings from `.proto` files run:

```bash
go generate ./...
```
