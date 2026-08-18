# Aptos Ledger Pruning — NOP Runbook

Runbook for Chainlink node operators (NOPs) running CCIP on Aptos. It covers enabling
30-day ledger pruning on your Aptos fullnode, what to monitor, and how to recover if the
node is offline longer than the pruning window.

For how the LogPoller detects pruned offsets, see [`PRUNED_RPC.md`](./PRUNED_RPC.md).

> **⚠️ Read before you bootstrap: fresh node / wiped Chainlink DB.**
> On a fresh or wiped Chainlink DB the LogPoller starts at offset `0` (genesis), which is
> already pruned on a pruning-enabled node — it will immediately trip the pruned warning.
> **Never cold-start a fresh relayer against a pruned node.** Follow
> [Fresh node / wiped Chainlink DB bootstrap](#fresh-node--wiped-chainlink-db-bootstrap)
> instead.

## Upgrade the Chainlink node

Chainlink Node **v2.57** version (which bundles the pruned-offset-aware
`chainlink-aptos` LOOP plugin) must be active before enabling pruning in the Aptos Node.

Confirm the node is healthy and CCIP lanes (commit/exec) are processing normally before
enabling pruning.

## Enable Aptos ledger pruning

Edit the **Aptos node** config (e.g. `fullnode.yaml`):

```yaml
storage:
  storage_pruner_config:
    ledger_pruner_config:
      enable: true
      prune_window: 360000000 # 360M transactions ≈ 30 days (based on 500 txs/h)
```

- `prune_window` is a **transaction count**, not a duration. `360000000` (360M) is a
  validated value targeting ~30 days at current mainnet throughput.
- **Aptos minimum is 100M.** A `prune_window` below 100M can cause runtime errors and
  damage node health. Do not go below it.

Restart the Aptos node, then verify the pruner is active:

- Node logs show the ledger pruner running.
- The node's `oldest_ledger_version` (from the `/v1` node-info endpoint, or the
  `X-APTOS-LEDGER-OLDEST-VERSION` response header) advances as old data is pruned.

## Metrics

| Metric                                   | Type      | Labels (extra)                  | Meaning                                                                                     |
| ---------------------------------------- | --------- | ------------------------------- | ------------------------------------------------------------------------------------------- |
| `aptos_log_poller_pruned_warning_active` | Gauge     | `eventHandle`, `eventFieldName` | `1` while a handle is in a pruned/gap warning state; `0` when recovered. **Paging signal.** |
| `aptos_log_poller_pruned_offset_total`   | Counter   | `eventHandle`, `eventFieldName` | Total pruned detections (increments each tick while pruned — shows duration/severity).      |
| `aptos_log_poller_event_sequence_gap`    | Counter   | `eventHandle`, `eventFieldName` | Total event sequence gap size detected.                                                     |
| `aptos_log_poller_fatal_error_total`     | Counter   | `eventHandle`, `eventFieldName` | Fatal (non-transient, non-pruned) RPC errors, e.g. 404 misconfiguration.                    |
| `aptos_log_poller_reader_lag_seconds`    | Histogram | `event`                         | Time from event block timestamp to local-DB insertion. Buckets 1s–3600s.                    |
| `aptos_log_poller_events_inserted`       | Counter   | `event`, `isSynthetic`          | Baseline throughput.                                                                        |

All metrics also carry `chainFamily`, `chainID`, `networkName`.

### Example alert rules

```yaml
groups:
  - name: aptos-logpoller
    rules:
      # Paging: a handle is in a pruned/gap warning state. See "Recovery" below.
      - alert: AptosLogPollerPrunedWarning
        expr: aptos_log_poller_pruned_warning_active == 1
        for: 5m
        labels:
          severity: page
        annotations:
          summary: "Aptos LogPoller pruned/gap warning on {{ $labels.eventFieldName }}"
          description: "Handle {{ $labels.eventHandle }} / {{ $labels.eventFieldName }} has been in a pruned/gap warning state for >5m. See the Recovery section of NOP_RUNBOOK."

      # Warning: sequence gaps mean events were skipped and must be backfilled.
      - alert: AptosLogPollerSequenceGap
        expr: increase(aptos_log_poller_event_sequence_gap[15m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Aptos LogPoller event sequence gap on {{ $labels.eventFieldName }}"

      # Warning: reader lag is elevated. Tunable threshold.
      - alert: AptosLogPollerReaderLagHigh
        expr: histogram_quantile(0.99, sum(rate(aptos_log_poller_reader_lag_seconds_bucket[15m])) by (le)) > 600
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Aptos LogPoller reader lag p99 > 10m"
```

The reader-lag p99 threshold (`600s` above) is a starting proposal — tune it to your SLA.
CCIP finality / OCR rounds are minutes-scale, so sustained p99 lag well above that warrants
investigation.

### Healthy state

In steady state with pruning enabled:

- `aptos_log_poller_pruned_warning_active == 0` for all handles.
- `aptos_log_poller_event_sequence_gap` does not increase.
- `aptos_log_poller_reader_lag_seconds` p99 stays under your threshold.
- `aptos_log_poller_events_inserted` advances with CCIP traffic.

## Recovery — offline longer than the 30-day window

**Trigger:** you are paged on `aptos_log_poller_pruned_warning_active == 1`, or this WARN
log appears:

```
syncEvent: pruned/gap warning raised — CR stays operational, NOP action required
```

The LogPoller's next offset falls in the pruned range: the node was offline (or the relayer
was down) long enough that the events it needs are gone from the pruned node. The CR keeps
operating and auto-recovers once it can read the missing range.

Restore a node that holds the missing range, point the relayer at it, let the poller
backfill, then switch back.

1. **Identify the affected handle** from the alert labels (`eventHandle`, `eventFieldName`)
   and the WARN log fields (`handle`, `field`, `layer`, `offset`, `oldestLedgerVersion`).
2. **Stand up a temporary node that has the missing range.** Restore only the range covering
   the gap — do not restore from genesis. Two snapshot sources:
   - **(Primary) Aptos Labs public backups.** Restore a DB covering the gap with
     `aptos node bootstrap-db` (Aptos CLI >= 1.0.14; needs AWS CLI or `gsutil`). Public
     backup adapter configs live in `aptos-labs/aptos-networks`:
     - Mainnet S3: `mainnet/backups/s3-public.yaml`
     - Mainnet GCS: `mainnet/backups/gcs.yaml`

     ```bash
     aptos node bootstrap-db \
       --ledger-history-start-version <start_of_gap> \
       --target-version <current_tip_or_later> \
       --command-adapter-config /path/to/s3-public.yaml \
       --target-db-dir /path/to/restore/db
     ```

     Set `--ledger-history-start-version` to the start of the gap (the poller's last synced
     version), never `0`. A full-history restore from genesis is not feasible — the DB
     cannot hold the entire chain history.

   - **(Alternative) NOP self-snapshot.** If you maintain your own snapshot covering the
     gap, restore it the same way. Keep snapshots fresh — a stale snapshot can make a NOP
     unrecoverable.

3. **Point the relayer's Aptos node URL at the temporary node** (update the
   `[[Aptos.Nodes]]` `URL` in the Chainlink TOML and restart the relayer, or fail over to
   the archive node URL).
4. **The LogPoller auto-recovers.** On the next sync it fetches the previously-pruned
   events from the temporary node, no pruned condition fires, and the warning gauge clears.
   Watch for the INFO log:

   ```
   syncEvent: pruned/gap warning cleared — handle recovered
   ```

5. **Handle sequence gaps explicitly.** If `aptos_log_poller_event_sequence_gap` increased,
   the poller inserted past a gap and the missing events in that range are **not**
   auto-recovered. Backfill them from the temporary node if they are required for CCIP
   correctness (e.g. a missing `MessageSent`).
6. **Verify recovery:** `aptos_log_poller_pruned_warning_active` returns to `0` and CCIP
   lanes are healthy.
7. **Switch back and decommission.** Point the relayer back at the steady-state pruned
   node, confirm the gauge stays `0`, then tear down the temporary node.

## Fresh node / wiped Chainlink DB bootstrap

> **⚠️ Do not skip this section.** Cold-starting a fresh relayer against a pruned node
> immediately trips the pruned warning and leaves the poller unable to sync. Read this
> before bootstrapping any new node or after wiping the Chainlink DB.

The LogPoller derives its starting offset from the local Postgres table `aptos.events`. On
a fresh or wiped Chainlink DB that table is empty, so the poller starts at offset `0`
(genesis) — already pruned on a pruning-enabled node, which immediately trips the pruned
warning.

**Do not cold-start a fresh relayer against a pruned node.** Instead:

1. Point the relayer at a node that holds history back to the first CCIP deployment (a
   node restored per the Recovery section above).
2. Let the poller backfill until it is caught up (the pruned warning clears and
   `aptos_log_poller_reader_lag_seconds` returns to normal).
3. Switch the relayer to the steady-state pruned node.

## Rollback

Re-disable pruning at any time; nothing in the relayer locks the choice in.

```yaml
storage:
  storage_pruner_config:
    ledger_pruner_config:
      enable: false
```

Restart the Aptos node. It returns to archival mode with unbounded disk growth — treat this
as a temporary measure, not a steady state.

## Troubleshooting

- **Paged on `aptos_log_poller_pruned_warning_active`?** See Recovery above. A handle's
  next offset is in the pruned range.
- **`aptos_log_poller_event_sequence_gap` increased?** Events were skipped and must be
  backfilled from an archive node (Recovery, step 5).
- **`aptos_log_poller_fatal_error_total` increasing?** Non-transient, non-pruned RPC error
  (e.g. 404 misconfiguration). Check the `[[Aptos.Nodes]]` URL and that the node serves the
  events API. Logged at Error; the CR does not halt.
- **Where are offsets stored?** In the Chainlink Postgres table `aptos.events`. The next
  offset is `MAX(event_offset) + 1` per `(event_account_address, event_handle,
event_field_name)`. There is no separate bookkeeping table.
- **410 vs empty vs caught up?** The poller distinguishes these automatically (see
  [`PRUNED_RPC.md`](./PRUNED_RPC.md)). You only act on the paging gauge.

## References

- [`PRUNED_RPC.md`](./PRUNED_RPC.md) — pruned-offset detection internals.
- [Aptos data pruning](https://aptos.dev/network/nodes/configure/data-pruning) — pruner config, 100M minimum.
- [Aptos DB restore](https://aptos.dev/network/nodes/bootstrap-fullnode/aptos-db-restore) — `aptos node bootstrap-db`, public backups.
- [Aptos state sync](https://aptos.dev/network/nodes/configure/state-sync) — bootstrapping modes.
