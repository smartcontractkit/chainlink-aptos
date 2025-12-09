## The Aptos Data Feeds contracts

The Data Feeds contracts folder contains the Registry and Router contracts.

The Registry receives and stores offchain reports from the Platform Forwader contract, and make available those report to users via the Router contract.

The Registry contract also contains a `get_feeds` view function to allow retrieval of all feed configs and latest reports, without the use of the Router contract.

The `legacy` folder contains the previous version of the `data-feeds` contract folder. This is used in e2e migration upgrade test, where we upgrade to support multiple Forwarders and the new single value benchmark report type.

## Why the `platform_secondary` folder exists

Due to a known limitation in the current Aptos VM build process, it's not yet possible to include two instances of the same package under different named addresses in a single dependency graph. As a result, to support multiple distinct `Forwarder` contracts at different addresses linked against the Data Feeds Registry contract. We duplicate the `platform` package into a separate folder named `platform_secondary`.

`platform_secondary` is meant to be an exact copy of the `platform` package, but with a different named address only. If `platform` is updated, `platform_secondary` should be regenerated from the latest `platform` package.

N.B.
Currently in the Move.toml for `platform_secondary`, we also need to rename the package name from "ChainlinkPlatform" to "ChainlinkPlatformSecondary".

This workaround allows the project to compile and function correctly while awaiting a proper upstream fix.

📄 Discussion: [Aptos Developer Discussions #694 (comment)](https://github.com/aptos-labs/aptos-developer-discussions/discussions/694#discussioncomment-13250748)

## How to run the Data Feeds e2e Scripts

During an upgrade to the Data Feeds Registry contract, a test script was made to simulate the migration in full on a local testnet.

```bash
cd contracts/data-feeds/scripts
./test_registry_migration_e2e.sh
```

This script can be adapted to prove/validate other future migrations, as well as a starting point for testing new development features.

There is also a vanilla, initial (non-upgrade) deploy script as well.

```bash
cd contracts/data-feeds/scripts
./test_registry_deploy_e2e.sh
```

## Aptos CLI

Install via `brew install aptos` (other options here: https://aptos.dev/build/cli). 


## Testing

Run tests under the `contracts/data-feeds` directory:

```bash
aptos move test --dev
```


### Run a specific test

```bash
aptos move test --dev --filter <test_name>
```
