## On-chain Data

### Get Data Feeds Events Emitted Across All Environments

This Go script retrieves data feed events emitted across all environments and transmitters. It generates different CSV files based on the specified environment (`staging`, `prod-testnet`, or `mainnet`). The output is sorted by block timestamp. This command also retrieves the timestamp of the most recent transaction.

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--environment` | `-e` | Environment (`staging`, `prod-testnet`, `mainnet`) | `staging` |
| `--lookback` | `-l` | Lookback period in hours. Paginates backwards from the most recent transaction per account to ensure complete time coverage. Use `0` to fetch all history. | `24` |
| `--feed-id` | `-f` | Filter by a specific feed ID. If omitted, returns events for all feeds. | (all feeds) |

```bash
# Last 24 hours, all feeds
go run . get-feed-updated-events -e mainnet

# Last 72 hours, single feed
go run . get-feed-updated-events -e mainnet -l 72 -f 0x011e22d6bf000332000000000000000000000000000000000000000000000000

# All history (slow — paginates from sequence 0)
go run . get-feed-updated-events -e mainnet -l 0
```

### Get Data Feeds Feed Updated Transaction for Given Report ID

This Go script helps to locate a specific reportID in the FeedUpdated events of Aptos feeds. Every workflow has a unique reportID that can be found in the forwarder transaction events. This script will search through the feed updates to find which feed contains the specified reportID, hence verifying the workflow execution.

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--environment` | `-e` | Environment (`staging`, `prod-testnet`, `mainnet`) | `staging` |
| `--reportId` | `-r` | Report ID to search | (required) |
| `--lookback` | `-l` | Lookback period in hours. Use `0` to fetch all history. | `24` |

```bash
# Search last 24 hours (default)
go run . find-workflow-report-id -e prod-testnet -r 18

# Search last 48 hours
go run . find-workflow-report-id -e prod-testnet -l 48 -r 18
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