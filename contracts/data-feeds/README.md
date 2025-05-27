## How to run the Data Feeds Migration e2e Script

During an upgrade to the Data Feeds Registry contract, a test script was made to simulate the migration in full on a local testnet.

cd contracts/data-feeds/scripts
./test_registry_migration_e2e.sh

This script can be adapted to prove other future migrations, as well as a starting point for testing new development features.

## Why the `platform_secondary` folder exists

Due to a known limitation in the current Aptos VM build process, it's not yet possible to include two instances of the same package under different named addresses in a single dependency graph. As a result, to support multiple distinct `Forwarder` contracts at different addresses, in the `data-feeds` Registry. We duplicate the `platform` package into a separate folder named `platform_secondary`.

This workaround allows the project to compile and function correctly while awaiting a proper upstream fix.

📄 Discussion: [Aptos Developer Discussions #694 (comment)](https://github.com/aptos-labs/aptos-developer-discussions/discussions/694#discussioncomment-13250748)
