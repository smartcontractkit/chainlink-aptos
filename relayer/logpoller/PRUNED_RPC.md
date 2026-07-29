# Pruned RPC Detection — Operator Runbook

This document describes how the Aptos LogPoller detects pruned event offsets, the warning
mechanism it uses, and the operator (NOP) recovery procedure. It is the single source of
truth referenced by code comments in `event_poller.go` and `event_errors.go`.

## Design philosophy

**The CR (LogPoller) does NOT halt when events are missing.** Instead, it stays operational
and raises a **warning** so the NOP can take action. The CR **auto-recovers** once the NOP
fixes the node. This avoids blocking all CCIP event ingestion while still surfacing the
problem for prompt operator intervention.

`HealthReport()` stays healthy — paging is **metric-based**, not health-based.

## The pruned-offset problem

Aptos nodes prune old ledger data to bound disk growth. When an event offset the LogPoller
needs falls in the pruned range, the node may respond in several ways — not all of them
obvious:

| Response | Observed? | Meaning |
|---|---|---|
| HTTP 410 Gone | Documented; not observed on localnet v1.42.1 | Explicit "data pruned" |
| HTTP 200 + `[]` (empty) | Yes | Offset beyond tip (caught-up) **or** pruned; disambiguated by EventHandle `counter` field |
| HTTP 200 + non-empty events | Yes (spike Phase 0b) | Events returned even though earlier offsets are pruned |
| `X-APTOS-LEDGER-OLDEST-VERSION` header | Present on observed responses (200, 410); may appear on others | Node-wide oldest ledger version |

The spike (`scripts/spike-pruned-rpc.sh`, Phase 0b) proved that a pruned offset can return
**HTTP 200 + 3 events** with no error. The events are real, but earlier events in the pruned
range are gone. The LogPoller must detect this to warn the NOP that events may be missing.

## Detection layers

The LogPoller uses three layers of defence:

### Layer 1 — RPC error classification (`event_errors.go`)

`ClassifyEventsRPCError` inspects errors from `EventsByCreationNumber`. Checks are applied
in order so that transient errors are never misclassified as Pruned (the
`X-APTOS-LEDGER-OLDEST-VERSION` header may be present on every response, including 429/5xx):

- **HTTP 410 Gone** → `ErrorClassPruned` (cheapest, most reliable signal; checked first)
- **HTTP 429 / 5xx** → `ErrorClassTransient` (retry next tick; checked before the header/body signals)
- **`X-APTOS-LEDGER-OLDEST-VERSION` header present on the error response** → `ErrorClassPruned` (corroborating signal, available via `HttpError.Header`)
- **Body JSON `error_code` is `"pruned"`/`"gone"`** (decoded via `encoding/json`, case-insensitive) → `ErrorClassPruned`
- **Body contains the bare substring `"pruned"` or `"410 gone"`** → `ErrorClassPruned` (belt-and-suspenders fallback for non-JSON bodies)
- **Other 4xx / parse error** → `ErrorClassFatal` (logged at Error, `fatal_error_total` metric; CR does not halt)
- **Unknown / network error** → `ErrorClassTransient` (safe: lets the poller retry)

> **Note on "gone" matching:** bare substring `"gone"` is intentionally NOT matched to avoid
> false positives (e.g. an unrelated error body containing the word "gone"). Only the
> structured JSON `error_code` field (decoded, so robust to whitespace/formatting), the
> literal `"410 gone"`, and the `"pruned"` substring are matched.

### Layer 2 — Counter-gated empty response check (`event_poller.go`)

When `EventsByCreationNumber` returns `[]` (empty), an empty page is ambiguous: the handle may be
caught up (no new events) OR the next offset may fall in the pruned range. The Aptos `EventHandle`
`counter` field (total events ever emitted, u64) disambiguates:

1. **Fetch the resource fresh** (not from cache) to read the current `counter` value.
   - The `counter` changes as events are emitted; `creation_num` is immutable and cached.
   - This adds one `AccountResource` RPC on the empty path only (the same path that previously
     called `Info()`, so RPC cost is unchanged).
2. **Compute `nextOffset`** = `MAX(event_offset) + 1` (already available from `GetLatestEventMeta`).
3. **If `nextOffset >= counter`** → the handle is caught up (no unseen events). Return nil, raise
   no warning, and do NOT call `Info()`.
4. **If `nextOffset < counter`** → there ARE unseen events. Fall through to the `Info()` heuristic
   below to determine whether the missing range is pruned.
5. **If counter extraction fails** → fall back to the existing `Info()` heuristic (fail-closed):
   - Extract error is logged at Debug; the poller continues to the Info check below.
   - If we cannot read the counter, trust the existing `Info()` oldest_ledger_version check
     rather than assume caught-up.

**Fallback: `Info()` oldest_ledger_version check** (when counter unavailable or nextOffset < counter):

1. Call `client.Info()` to get `oldest_ledger_version`.
2. If `lastTxVersion < oldest_ledger_version` → the stored offset is in the pruned range → raise warning.
3. **If `Info()` errors** → fail closed: return a transient error. Do NOT assume caught-up. A node
   outage must not mask a pruned offset.
4. **If `oldest_ledger_version` is 0 (parse failure)** but `ledger_version` is valid → fail closed:
   return a transient error. The SDK's `OldestLedgerVersion()` returns 0 on parse failure without
   error; we treat this as "cannot verify, do not assume safe."

**Key improvement**: Quiet handles (no new events in a while) have `lastTxVersion < oldest` even
when fully caught up. The counter gate eliminates this false positive by checking whether there
are unseen events (nextOffset < counter) before consulting the Info heuristic.

### Layer 3 — Non-empty pruned detection via response header (`event_poller.go` + `chain/headercapture.go`)

When `EventsByCreationNumber` returns **non-empty** events, the LogPoller checks whether the
first event's `Version` is below the node's `oldest_ledger_version`:

1. **Preferred:** read the `X-APTOS-LEDGER-OLDEST-VERSION` header captured by the
   `HeaderCapturingRoundTripper` (injected into the Aptos node's `*http.Client` at
   `chain.go`). The aptos-go-sdk discards response headers on 2xx responses, so a custom
   `http.RoundTripper` intercepts `/events/` responses and atomically stores the header.
2. **Fallback:** if the header is unavailable, call `client.Info()` (only when stored events
   exist, to avoid an extra RPC on fresh handles).
3. If `events[0].Version < oldest_ledger_version` → raise warning. **The events are still
   inserted and the offset advances** — they're real events. The warning tells the NOP that
   earlier events in the pruned range may be missing and need archive-node reindex.

> **Concurrency note:** `EventsByCreationNumber` issues a single HTTP request when
> `limit ≤ 100` (the default `EventBatchSize`). When `limit > 100` it fans out into
> concurrent goroutines. The header is node-wide (identical across pages), so "last writer
> wins" via atomic store is semantically correct.

## Sequence gaps

When the first event in a batch has `SequenceNumber > latestOffset` (a gap), the LogPoller:

1. Increments the `aptos_log_poller_event_sequence_gap` counter by the gap size.
2. Raises a warning (gauge → 1).
3. **Inserts the events it received and advances the offset past the gap.** The CR keeps
   moving. The missing events are flagged for archive-node reindex.

The gap is a one-time event; the warning auto-clears on the next successful sync with no gap.

## Warning mechanism

The warning is surfaced via a Prometheus gauge, **not** `HealthReport`:

| Metric | Type | Meaning |
|---|---|---|
| `aptos_log_poller_pruned_warning_active` | Gauge | `1` while a handle is in pruned/gap warning state; `0` when recovered. **Paging signal.** |
| `aptos_log_poller_pruned_offset_total` | Counter | Total pruned detections (increments each tick while pruned — shows duration/severity). |
| `aptos_log_poller_event_sequence_gap` | Counter | Total sequence gap size detected. |
| `aptos_log_poller_fatal_error_total` | Counter | Total fatal (non-transient, non-pruned) RPC errors. |

**Wire Prometheus alert rules** to page the NOP when `aptos_log_poller_pruned_warning_active`
is `1` for more than N minutes (e.g. 5 min).

### Rate-limited logging

- **First detection** (transition into warned state): logged at `WARN` with full context
  (handle, field, offset, lastTxVersion, oldestLedgerVersion, layer, recoveryAction).
- **Subsequent ticks** (already warned): logged at `DEBUG` to avoid per-tick spam.
- **Recovery** (warning cleared): logged at `INFO`.

### Auto-recovery

The warning auto-clears when a subsequent `syncEvent` for the handle completes without hitting
any pruned/gap condition. This happens naturally when the NOP switches to an archive node:
the LogPoller syncs the previously-pruned events, no pruned condition fires, and the warning
clears. No manual reset is needed.

## NOP recovery procedure

When paged on `aptos_log_poller_pruned_warning_active = 1`:

1. **Identify the affected handle** from the alert labels (`event` = event field name) and
   the WARN log (`handle`, `field`, `layer`).
2. **Switch the relayer's Aptos node to an archive node** (or a node with a larger prune
   window). Update the node config and restart the relayer, or point to an archive node URL.
3. **The LogPoller will auto-recover**: on the next sync, it fetches the previously-pruned
   events from the archive node, no pruned condition fires, and the warning gauge clears.
4. **For sequence gaps**: the missing events in the gap range need to be reindexed from the
   archive node. The LogPoller advances past the gap, so the missing events are not
   automatically recovered — they must be backfilled separately if required for CCIP
   correctness (e.g. missing `MessageSent` events).
5. **Verify recovery**: confirm `aptos_log_poller_pruned_warning_active` returns to `0` and
   the `INFO` log "pruned/gap warning cleared — handle recovered" appears.

## aptos-go-sdk v1.13.0 notes

- The SDK discards HTTP response headers on successful (2xx) responses — only
  `HttpError.Header` is populated on error (≥400) responses. This is why Layer 3 requires a
  custom `http.RoundTripper` to capture `X-APTOS-LEDGER-OLDEST-VERSION` on the success path.
- `NodeInfo.OldestLedgerVersion()` parses `oldest_ledger_version` from the node-info JSON
  body (not the header). It returns `0` on parse failure with no error — Layer 2 handles this
  by failing closed when `ledger_version` is valid but `oldest_ledger_version` is 0.
- `EventsByCreationNumber` issues a single HTTP request when `limit ≤ 100`; fans out into
  concurrent goroutines when `limit > 100`. The `HeaderCapturingRoundTripper` uses atomic
  store ("last writer wins") which is safe because the header is node-wide.
