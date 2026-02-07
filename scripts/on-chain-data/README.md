## On-chain Data

### Get Data Feeds Events Emitted Across All Environments

This Go script retrieves data feed events emitted across all environments and transmitters. It generates different CSV files based on the specified environment (`staging`, `prod-testnet`, or `mainnet`). Use -l to include only the latest transactions. This command also retrieves the timestamp of the most recent transaction.

```bash
go run . get-feed-updated-events -e mainnet -l
```

### Get Data Feeds Feed Updated Transaction for Given Report ID 

This Go script helps to locate a specific reportID in the FeedUpdated events of Aptos feeds. You can specify the environment (`staging`, `prod-testnet`, or `mainnet`), the report ID (-r) and use -l to include only the latest transactions. Every workflow has a unique reportID that can be found in the forwarder transaction events. This script will search through the feed updates to find which feed contains the specified reportID, hence verifying the workflow execution.

```bash
go run . find-workflow-report-id -e prod-testnet -l -r 18
```

### Compute Data Feed Events Metrics from previous step

This Go script computes metrics such as the average, minimum, maximum, p90, p95, p99, and SLA for the overall set of events, as well as split by feed. Additionally, it retrieves statistics on the gas used to process all feeds and identifies slow transactions. You can specify a timeframe with the -l parameter to include only the events that occurred in the last -t seconds.

```bash
go run . compute-data-feed-updated-events-metrics -i aptos-data-feed-events-prod-testnet-latest.csv -t 864000
```

### Get Account Balances

This Go script retrieves the balance of accounts in a given environment.

```bash
go run . get-account-balances -e prod-testnet 
```