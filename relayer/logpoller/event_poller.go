package logpoller

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/types"

	aptostypes "github.com/smartcontractkit/chainlink-common/pkg/types/aptos"

	"github.com/smartcontractkit/chainlink-aptos/codec"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitoring/prom"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

func (l *AptosLogPoller) startEventPolling(ctx context.Context) {
	l.lggr.Infow("Event polling goroutine started")
	defer l.lggr.Infow("Event polling goroutine exited")

	ticker := time.NewTicker(l.config.EventPollingInterval.Duration())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, l.config.PollTimeout.Duration())
			start := time.Now()

			err := l.SyncAllEvents(syncCtx)
			elapsed := time.Since(start)

			if err != nil {
				l.lggr.Warnw("EventSync completed with errors",
					"error", err,
					"duration", elapsed)
			} else {
				l.lggr.Debugw("Event sync completed successfully",
					"duration", elapsed)
			}

			cancel()
		case <-ctx.Done():
			l.lggr.Infow("Event polling stopped")
			return
		}
	}
}

func (l *AptosLogPoller) SyncAllEvents(ctx context.Context) error {
	start := time.Now()

	if l.dbStore == nil {
		return fmt.Errorf("SyncAllEvents only operates in persistent mode")
	}

	// Avoid locking durring the potentially long operation
	l.mu.RLock()
	modulesCopy := make(map[string]*moduleInfo)
	maps.Copy(modulesCopy, l.modules)
	l.mu.RUnlock()

	successCount := 0
	errorCount := 0
	var lastErr error

	for moduleKey, moduleInfo := range modulesCopy {
		if moduleInfo.eventConfigs == nil {
			continue
		}

		for eventKey, eventConfig := range moduleInfo.eventConfigs {
			select {
			case <-ctx.Done():
				elapsed := time.Since(start)
				if successCount > 0 {
					l.lggr.Infow("SyncAllEvents: interrupted, some events synced",
						"successCount", successCount,
						"errorCount", errorCount,
						"duration", elapsed)
				} else {
					l.lggr.Infow("SyncAllEvents: interrupted before processing any events",
						"duration", elapsed)
				}

				return ctx.Err()
			default:
				err := l.syncEvent(ctx, moduleInfo.address, eventConfig, moduleInfo.name)
				if err != nil {
					errorCount++
					lastErr = fmt.Errorf("SyncAllEvents: module %s event %s: %w", moduleKey, eventKey, err)
					l.lggr.Errorw("SyncAllEvents: error syncing event", "module", moduleKey, "event", eventKey, "error", err)
				} else {
					successCount++
				}
			}
		}
	}

	elapsed := time.Since(start)
	if errorCount > 0 {
		l.lggr.Errorw("SyncAllEvents: completed with errors",
			"successCount", successCount,
			"errorCount", errorCount,
			"lastError", lastErr,
			"duration", elapsed)
		return lastErr
	}

	l.lggr.Infow("SyncAllEvents: successfully synced all events",
		"count", successCount,
		"duration", elapsed)
	return nil
}

func (l *AptosLogPoller) SyncEvent(ctx context.Context, moduleKey, eventKey string) error {
	l.mu.RLock()
	info, exists := l.modules[moduleKey]
	if !exists {
		l.mu.RUnlock()
		return fmt.Errorf("module %s not registered", moduleKey)
	}

	eventConfig, exists := info.eventConfigs[eventKey]
	if !exists {
		l.mu.RUnlock()
		return fmt.Errorf("event %s not configured for module %s", eventKey, moduleKey)
	}

	address := info.address
	name := info.name
	l.mu.RUnlock()

	err := l.syncEvent(ctx, address, eventConfig, name)

	return err
}

func (l *AptosLogPoller) syncEvent(ctx context.Context, boundAddress aptos.AccountAddress, eventConfig *aptostypes.ContractReaderEvent, eventModuleName string) error {
	start := time.Now()

	eventAccountAddress, err := l.computeEventAccountAddress(boundAddress, eventConfig)
	if err != nil {
		return fmt.Errorf("syncEvent: %w", err)
	}

	eventHandle := boundAddress.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName
	eventFieldName := eventConfig.EventHandleFieldName
	hKey := handleKey(eventHandle, eventFieldName)

	latestOffset, lastTxVersion, hasStoredEvents, err := l.evStore.GetLatestEventMeta(ctx, eventAccountAddress.String(), eventHandle, eventFieldName)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to get latest event meta: %w", err)
	}

	cacheKey := eventAccountAddress.String() + "::" + eventHandle
	resourceAny, found := l.resourceCache.Get(cacheKey)
	var resource map[string]any

	if !found {
		var client aptos.AptosRpcClient
		client, err = l.getClient()
		if err != nil {
			return fmt.Errorf("failed to get client: %w", err)
		}
		resource, err = client.AccountResource(eventAccountAddress, eventHandle)
		if err != nil {
			return fmt.Errorf("syncEvent: failed to fetch the resource: %w", err)
		}

		// store permanently since event creation ids don't change
		l.resourceCache.Set(cacheKey, resource, cache.NoExpiration)
		l.lggr.Debugw("Resource cached", "key", cacheKey)
	} else {
		var ok bool
		resource, ok = resourceAny.(map[string]any)
		if !ok {
			l.lggr.Errorw("Failed to cast cached resource to map[string]any", "key", cacheKey)
			var client aptos.AptosRpcClient
			client, err = l.getClient()
			if err != nil {
				return fmt.Errorf("failed to get client: %w", err)
			}
			resource, err = client.AccountResource(eventAccountAddress, eventHandle)
			if err != nil {
				return fmt.Errorf("syncEvent: failed to fetch the resource after cache cast failure: %w", err)
			}
			l.resourceCache.Set(cacheKey, resource, cache.NoExpiration)
		}
	}

	creationNumber, err := crutils.ExtractEventCreationNum(resource, eventFieldName)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to extract creation_num for %s: %w", eventFieldName, err)
	}

	batchSize := *l.config.EventBatchSize
	var totalProcessed int = 0
	warnedThisTick := false // set when a pruned/gap warning is raised this tick; blocks auto-recovery

	var client aptos.AptosRpcClient
	client, err = l.getClient()
	if err != nil {
		return fmt.Errorf("failed to get client: %w", err)
	}

eventLoop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			events, err := client.EventsByCreationNumber(eventAccountAddress, creationNumber, &latestOffset, &batchSize)
			if err != nil {
				class := ClassifyEventsRPCError(err)
				if class == ErrorClassPruned {
					// Layer 1: RPC error classification (HTTP 410 / "pruned" body / header).
					// CR does NOT halt: raise a warning so the NOP can act (archive node).
					prom.ReportPrunedOffset(l.chainInfo, eventFieldName)
					l.raisePrunedWarning(hKey, eventHandle, eventFieldName,
						"offset", latestOffset,
						"layer", "rpc-error",
						"error", err)
					// Return the error so SyncAllEvents logs it; the next tick retries.
					// HealthReport stays healthy — paging is metric-based.
					return fmt.Errorf("syncEvent: %w", ErrPrunedOffset)
				}
				if class == ErrorClassFatal {
					// Fatal (e.g. 404 misconfig): log loudly, increment fatal counter.
					// CR does NOT halt per design; NOP should investigate the config.
					prom.ReportFatalError(l.chainInfo, eventFieldName)
					l.lggr.Errorw("syncEvent: fatal RPC error fetching events (non-transient, non-pruned)",
						"handle", eventHandle, "field", eventFieldName, "error", err)
					return fmt.Errorf("syncEvent: failed to fetch events: %w", err)
				}
				// Transient (5xx/429/network): retry next tick.
				l.lggr.Warnw("syncEvent: transient error fetching events", "error", err)
				return fmt.Errorf("syncEvent: failed to fetch events: %w", err)
			}

			if len(events) == 0 {
				// Layer 2: defensive pruned check on empty response. If we have stored
				// events and the highest stored tx_version is below the node's
				// oldest_ledger_version, the offset falls in the pruned range even though
				// the API returned 200 + [] rather than 410. See PRUNED_RPC.md.
				if hasStoredEvents {
					nodeInfo, infoErr := client.Info()
					if infoErr != nil {
						// Fail closed: if Info() errors we cannot verify pruning, so do NOT
						// assume caught-up. Return a transient error so the next tick retries.
						// This prevents a node outage from masking a pruned offset.
						l.lggr.Warnw("syncEvent: defensive pruned check skipped — Info() failed",
							"handle", eventHandle, "field", eventFieldName, "error", infoErr)
						return fmt.Errorf("syncEvent: defensive pruned check unavailable: %w", infoErr)
					}
					oldest := nodeInfo.OldestLedgerVersion()
					if oldest == 0 {
						// OldestLedgerVersion() returns 0 on parse failure (SDK limitation).
						// If the node reports a valid ledger_version but an unparseable
						// oldest_ledger_version, we cannot verify pruning — fail closed.
						if nodeInfo.LedgerVersionStr != "" {
							l.lggr.Warnw("syncEvent: oldest_ledger_version unparseable, cannot verify pruning",
								"handle", eventHandle, "field", eventFieldName,
								"oldestLedgerVersionStr", nodeInfo.OldestLedgerVersionStr,
								"ledgerVersionStr", nodeInfo.LedgerVersionStr)
							return fmt.Errorf("syncEvent: oldest_ledger_version unparseable, cannot verify pruning")
						}
						// Both zero: node genuinely returning zeros; treat as caught-up.
					} else if lastTxVersion < oldest {
						prom.ReportPrunedOffset(l.chainInfo, eventFieldName)
						l.raisePrunedWarning(hKey, eventHandle, eventFieldName,
							"lastTxVersion", lastTxVersion,
							"oldestLedgerVersion", oldest,
							"offset", latestOffset,
							"layer", "empty-info")
						return fmt.Errorf("syncEvent: %w", ErrPrunedOffset)
					}
				}
				break eventLoop
			}

			// Non-empty pruned check (Layer 3): the spike proved a pruned offset can return
			// HTTP 200 + events whose tx_version < oldest_ledger_version. Detect via the
			// captured X-APTOS-LEDGER-OLDEST-VERSION header (or Info() fallback). CR does
			// NOT halt: insert the events, advance the offset, but raise a warning so the
			// NOP can reindex any missing events from an archive node.
			if pruned, oldest := l.checkNonEmptyPruned(client, events, hasStoredEvents); pruned {
				prom.ReportPrunedOffset(l.chainInfo, eventFieldName)
				l.raisePrunedWarning(hKey, eventHandle, eventFieldName,
					"firstEventVersion", events[0].Version,
					"oldestLedgerVersion", oldest,
					"offset", latestOffset,
					"layer", "nonempty-header")
				warnedThisTick = true
				// Fall through: still insert the events we received (they're real) and
				// advance the offset. The warning tells the NOP that earlier events in the
				// pruned range may be missing and need archive-node reindex.
			}

			// Sequence gap check: detect missing events between the stored offset and the
			// first event in this batch. CR does NOT halt: insert the events we received,
			// advance past the gap, and raise a warning so the NOP can reindex the missing
			// events from an archive node. The gap is a one-time event we move past.
			if events[0].SequenceNumber > latestOffset {
				gapSize := events[0].SequenceNumber - latestOffset
				prom.ReportEventSequenceGap(l.chainInfo, eventFieldName, gapSize)
				l.raisePrunedWarning(hKey, eventHandle, eventFieldName,
					"expectedOffset", latestOffset,
					"firstEventOffset", events[0].SequenceNumber,
					"gapSize", gapSize,
					"layer", "sequence-gap")
				warnedThisTick = true
			}

			var batchRecords []db.EventRecord
			for _, event := range events {
				head, err := l.getBlockHead(event.Version)
				if err != nil {
					l.lggr.Errorw("syncEvent: failed to fetch block metadata", "version", event.Version, "error", err)
					continue
				}

				if err := crutils.RenameMapFields(event.Data, eventConfig.EventFieldRenames); err != nil {
					l.lggr.Errorw("syncEvent: failed to rename event fields", "error", err)
					continue
				}

				record := db.EventRecord{
					EventAccountAddress: eventAccountAddress.String(),
					EventHandle:         eventHandle,
					EventFieldName:      eventFieldName,
					EventOffset:         event.SequenceNumber,
					TxVersion:           event.Version,
					BlockHeight:         head.Height,
					BlockHash:           head.Hash,
					BlockTimestamp:      head.Timestamp,
					Data:                event.Data,
				}
				batchRecords = append(batchRecords, record)
			}

			if len(batchRecords) > 0 {
				if err := l.evStore.InsertEvents(ctx, batchRecords); err != nil {
					return fmt.Errorf("syncEvent: failed to insert batch of events: %w", err)
				}

				prom.ReportEventsInserted(l.chainInfo, eventFieldName, false, len(batchRecords))

				// Reader lag: time between block timestamp (seconds) and now.
				for _, record := range batchRecords {
					if record.BlockTimestamp > 0 {
						lagSeconds := float64(time.Now().Unix() - int64(record.BlockTimestamp))
						prom.ObserveReaderLag(l.chainInfo, eventFieldName, lagSeconds)
					}
				}

				// Update defensive-check state for subsequent iterations.
				lastTxVersion = batchRecords[len(batchRecords)-1].TxVersion
				hasStoredEvents = true

				totalProcessed += len(batchRecords)
				l.lggr.Debugw("syncEvent: saved batch of events",
					"batch_count", len(batchRecords),
					"total_processed", totalProcessed,
					"handle", eventHandle,
					"field", eventFieldName)
			}

			latestOffset = events[len(events)-1].SequenceNumber + 1

			// If we received fewer events than the batch size, we're caught up.
			if uint64(len(events)) < batchSize {
				break eventLoop
			}
		}
	}

	// Auto-recovery: if this handle was previously warned but no pruned/gap condition was
	// hit this tick, clear the warning. The NOP switching to an archive node → CR syncs the
	// pruned events → no pruned condition fires → warning clears automatically. We only
	// clear when warnedThisTick is false so a warning raised during this sync is preserved.
	if !warnedThisTick && l.isHandleWarned(hKey) {
		l.clearPrunedWarning(hKey, eventHandle, eventFieldName)
	}

	elapsed := time.Since(start)
	if totalProcessed > 0 {
		l.lggr.Infow("syncEvent: events synced",
			"count", totalProcessed,
			"handle", eventHandle,
			"field", eventFieldName,
			"account", eventAccountAddress.String(),
			"duration", elapsed)
	} else {
		l.lggr.Debugw("syncEvent: no new events to sync",
			"handle", eventHandle,
			"field", eventFieldName,
			"account", eventAccountAddress.String(),
			"duration", elapsed)
	}

	return nil
}

// raisePrunedWarning transitions a handle into the pruned/gap warning state. On the first
// detection (not already warned) it logs at Warn with full context and sets the
// aptos_log_poller_pruned_warning_active gauge to 1 (the NOP paging signal). On subsequent
// ticks it logs at Debug to avoid spam. The CR does NOT halt — it stays operational and
// auto-recovers via clearPrunedWarning once the NOP fixes the node. Returns the first-warn
// timestamp (zero if already warned).
func (l *AptosLogPoller) raisePrunedWarning(handleKey, eventHandle, eventFieldName string, fields ...any) {
	l.mu.Lock()
	firstWarn := l.markWarned(handleKey)
	l.mu.Unlock()

	prom.SetPrunedWarning(l.chainInfo, eventFieldName, true)

	if firstWarn {
		// First detection: prominent warning with full context for the NOP.
		allFields := append([]any{
			"handle", eventHandle,
			"field", eventFieldName,
			"recoveryAction", "switch to archive node or reindex missing events; CR stays operational and will auto-recover",
		}, fields...)
		l.lggr.Warnw("syncEvent: pruned/gap warning raised — CR stays operational, NOP action required", allFields...)
	} else {
		// Already warned: quiet log to avoid per-tick spam.
		l.lggr.Debugw("syncEvent: pruned/gap warning still active", "handle", eventHandle, "field", eventFieldName)
	}
}

// clearPrunedWarning removes a handle from the warned state (auto-recovery). Called when a
// sync succeeds past the pruned range. Sets the gauge to 0 and logs at Info so the NOP can
// see the recovery. Returns true if the handle was warned and is now cleared.
func (l *AptosLogPoller) clearPrunedWarning(handleKey, eventHandle, eventFieldName string) bool {
	l.mu.Lock()
	cleared := l.clearWarned(handleKey)
	l.mu.Unlock()

	if cleared {
		prom.SetPrunedWarning(l.chainInfo, eventFieldName, false)
		l.lggr.Infow("syncEvent: pruned/gap warning cleared — handle recovered",
			"handle", eventHandle, "field", eventFieldName)
	}
	return cleared
}

// isHandleWarned reports whether a handle is currently in the pruned/gap warning state.
func (l *AptosLogPoller) isHandleWarned(handleKey string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.isWarned(handleKey)
}

// checkNonEmptyPruned detects pruning on the non-empty events path. The spike (Phase 0b)
// proved a pruned offset can return HTTP 200 + events whose tx_version is below the node's
// oldest_ledger_version. The aptos-go-sdk discards response headers on 2xx, so we read the
// X-APTOS-LEDGER-OLDEST-VERSION header captured by the chain's HeaderCapturingRoundTripper
// (l.oldestLedgerVersionProvider). Falls back to an Info() call when the provider is unset
// or has no captured value. Returns true if the first event's Version is below the oldest
// ledger version (pruned). The CR does NOT halt in this case — events are still inserted
// and the offset advances, but a warning is raised so the NOP can reindex missing events.
func (l *AptosLogPoller) checkNonEmptyPruned(client aptos.AptosRpcClient, events []*api.Event, hasStoredEvents bool) (pruned bool, oldestLedgerVersion uint64) {
	if len(events) == 0 {
		return false, 0
	}
	firstVersion := events[0].Version

	// Preferred path: read the captured response header (no extra RPC).
	if l.oldestLedgerVersionProvider != nil {
		if v, ok := l.oldestLedgerVersionProvider.LastOldestLedgerVersion(); ok {
			if firstVersion < v {
				return true, v
			}
			return false, v
		}
	}

	// Fallback: only call Info() when we have stored events (avoid extra RPC on fresh
	// handles). This is belt-and-suspenders for when the header is unavailable.
	if !hasStoredEvents {
		return false, 0
	}
	nodeInfo, infoErr := client.Info()
	if infoErr != nil {
		// Can't determine — don't false-positive. The empty-path Info() check handles
		// the fail-closed semantics; here we just can't corroborate.
		return false, 0
	}
	oldest := nodeInfo.OldestLedgerVersion()
	if oldest == 0 {
		return false, 0 // unparseable; can't determine
	}
	if firstVersion < oldest {
		return true, oldest
	}
	return false, oldest
}

func (l *AptosLogPoller) computeEventAccountAddress(boundAddress aptos.AccountAddress, eventConfig *aptostypes.ContractReaderEvent) (aptos.AccountAddress, error) {
	var eventAccountAddress aptos.AccountAddress
	if len(eventConfig.EventAccountAddress) == 0 {
		return boundAddress, nil
	}

	components := strings.Split(eventConfig.EventAccountAddress, "::")
	if len(components) == 1 {
		err := eventAccountAddress.ParseStringRelaxed(components[0])
		if err != nil {
			return eventAccountAddress, fmt.Errorf("failed to parse event account address: %+w", err)
		}
		return eventAccountAddress, nil
	} else {
		var addressFunctionAddress aptos.AccountAddress
		var addressFunctionModuleName, addressFunctionFunctionName string
		if len(components) == 3 {
			err := addressFunctionAddress.ParseStringRelaxed(components[0])
			if err != nil {
				return eventAccountAddress, fmt.Errorf("failed to parse event account address function address: %+w", err)
			}
			addressFunctionModuleName = components[1]
			addressFunctionFunctionName = components[2]
		} else if len(components) == 2 {
			addressFunctionAddress = boundAddress
			addressFunctionModuleName = components[0]
			addressFunctionFunctionName = components[1]
		} else {
			return eventAccountAddress, fmt.Errorf("invalid event account address definition: %s", eventConfig.EventAccountAddress)
		}

		cacheKey := addressFunctionAddress.String() + "::" + addressFunctionModuleName + "::" + addressFunctionFunctionName

		if cached, ok := l.getEventAccountAddress(cacheKey); ok {
			return cached, nil
		}

		viewPayload := &aptos.ViewPayload{
			Module: aptos.ModuleId{
				Address: addressFunctionAddress,
				Name:    addressFunctionModuleName,
			},
			Function: addressFunctionFunctionName,
			ArgTypes: []aptos.TypeTag{},
			Args:     [][]byte{},
		}

		client, err := l.getClient()
		if err != nil {
			return eventAccountAddress, err
		}
		data, err := client.View(viewPayload)
		if err != nil {
			return eventAccountAddress, fmt.Errorf("failed to call view function: %+w", err)
		}

		err = codec.DecodeAptosJsonValue(data[0], &eventAccountAddress)
		if err != nil {
			return eventAccountAddress, fmt.Errorf("failed to decode event account address function output: %+w", err)
		}

		l.setEventAccountAddress(cacheKey, eventAccountAddress)

		return eventAccountAddress, nil
	}
}

func (l *AptosLogPoller) getBlockHead(version uint64) (types.Head, error) {
	var block *api.Block
	var err error

	cacheKey := fmt.Sprintf("block-%d", version)
	if cachedBlockAny, found := l.blockCache.Get(cacheKey); found {
		var ok bool
		block, ok = cachedBlockAny.(*api.Block)
		if !ok {
			l.lggr.Errorw("Failed to cast cached block to *api.Block", "key", cacheKey)
			var client aptos.AptosRpcClient
			client, err = l.getClient()
			if err != nil {
				return types.Head{}, fmt.Errorf("failed to get client: %w", err)
			}
			block, err = client.BlockByVersion(version, false)
			if err != nil {
				return types.Head{}, fmt.Errorf("failed to get block by version after cache cast failure: %w", err)
			}
			l.blockCache.Set(cacheKey, block, cache.DefaultExpiration)
		} else {
			l.lggr.Debugw("Using cached block", "version", version)
		}
	} else {
		var client aptos.AptosRpcClient
		client, err = l.getClient()
		if err != nil {
			return types.Head{}, fmt.Errorf("failed to get client: %w", err)
		}
		block, err = client.BlockByVersion(version, false)
		if err != nil {
			return types.Head{}, fmt.Errorf("failed to get block by version: %w", err)
		}

		l.blockCache.Set(cacheKey, block, cache.DefaultExpiration)
		l.lggr.Debugw("Block cached", "version", version)
	}

	hexBytes, err := utils.DecodeHexRelaxed(block.BlockHash)
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to decode block hash: %w", err)
	}

	head := types.Head{
		Height:    fmt.Sprintf("%d", block.BlockHeight),
		Hash:      hexBytes,
		Timestamp: block.BlockTimestamp / 1000000, // microseconds to seconds conversion
	}

	return head, nil
}
