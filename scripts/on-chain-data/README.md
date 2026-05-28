## On-chain Data

Go CLI tools for investigating Aptos data feed transmissions. Run all commands from this directory:

```bash
cd scripts/on-chain-data
go run . <command> [flags]
```

### Commands

| Command | Purpose |
|---------|---------|
| `get-feed-updated-events` | Fetch raw `FeedUpdated` events to CSV |
| `get-feed-gaps` | Fetch updates and compute observation gaps per feed |
| `check-heartbeat-misses` | Find observation gaps in a CSV that exceed configured heartbeats |
| `compute-data-feed-updated-events-metrics` | Latency/gas metrics from a events CSV |
| `find-workflow-report-id` | Find which feed contains a report ID |
| `get-account-balances` | Writer account balances |

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

### Get Feed Gaps

Fetches all on-chain feed updates in a lookback window and computes the observation gap since each feed's previous update. Does not require a feed list or heartbeat config — all feeds seen on-chain in the window are included.

**Flags:**

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--environment` | `-e` | Environment (`staging`, `prod-testnet`, `mainnet`) | `staging` |
| `--minutes` | `-m` | Lookback period in minutes | (required) |

```bash
# Last 2 hours on mainnet
go run . get-feed-gaps -e mainnet -m 120

# Last 40 minutes
go run . get-feed-gaps -e mainnet -m 40
```

**Outputs:**

| File | Description |
|------|-------------|
| `aptos-feed-gaps-<env>-<minutes>m-<timestamp>.csv` | Timestamped snapshot |
| `aptos-feed-gaps-<env>-latest.csv` | Copy of the most recent run |

**CSV columns:** `feed_id`, `observation_time_utc`, `observation_timestamp`, `gap_since_last_update_s`, `block_time_utc`, `block_timestamp`, `transaction_hash`, `benchmark`, `success`, `gas_used`

Notes:
- One row per deduped feed observation in the window (multiple writer txs for the same observation are collapsed).
- `gap_since_last_update_s` is blank for the first row per feed in the window; otherwise it is seconds since the previous observation for that feed.
- Multiple feeds updated in the same batch share the same `transaction_hash`.

**Terminal summary** (concise — full gap list is in the CSV):
- Window, feed count, update count, gap count
- Top 20 largest gaps, one line per feed
- Per-feed min/max gap stats

### Check Heartbeat Misses

Scans a `get-feed-updated-events` CSV for **provable** heartbeat breaches. For each configured feed, observations are sorted by `observation_timestamp`, consecutive gaps are computed, and any gap greater than the configured heartbeat is reported. No wall-clock time is used — results depend only on the CSV contents.

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | FeedUpdated events CSV from `get-feed-updated-events` | (required) |
| `--config` | `-c` | JSON file with `stream_id`, `feed_id`, and `heartbeat` (seconds) | (required) |

```bash
go run . check-heartbeat-misses \
  -i aptos-data-feed-events-mainnet-latest.csv \
  -c examples/heartbeat-config.mainnet.json
```

Example config: `examples/heartbeat-config.mainnet.json`

### Example workflow: heartbeat investigation

```bash
# 1. Fetch recent on-chain updates and gap analysis
go run . get-feed-gaps -e mainnet -m 120

# 2. Find heartbeat breaches in the exported events
go run . get-feed-updated-events -e mainnet -l 2
go run . check-heartbeat-misses \
  -i aptos-data-feed-events-mainnet-latest.csv \
  -c examples/heartbeat-config.mainnet.json

# 3. Optional: latency/gas metrics from the events CSV
go run . compute-data-feed-updated-events-metrics \
  -i aptos-data-feed-events-mainnet-latest.csv
```

### Compute Data Feed Events Metrics from previous step

This Go script computes metrics such as the average, minimum, maximum, p90, p95, p99, and SLA for the overall set of events, as well as split by feed. Additionally, it retrieves statistics on the gas used to process all feeds and identifies slow transactions. Use `-t` to include only events from the last N seconds.

```bash
go run . compute-data-feed-updated-events-metrics -i aptos-data-feed-events-prod-testnet-latest.csv -t 864000
```

### Get Account Balances

This Go script retrieves the balance of accounts in a given environment.

```bash
go run . get-account-balances -e prod-testnet 
```