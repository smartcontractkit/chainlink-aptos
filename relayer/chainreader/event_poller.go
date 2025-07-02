package chainreader

import (
	"context"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
)

func (a *aptosChainReader) startEventPolling(ctx context.Context) {
	a.lggr.Infow("Event polling goroutine started")
	defer a.lggr.Infow("Event polling goroutine exited")

	ticker := time.NewTicker(a.config.EventSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, a.config.EventSyncTimeout)
			start := time.Now()

			err := a.SyncAllEvents(syncCtx)
			elapsed := time.Since(start)

			if err != nil && err != context.DeadlineExceeded {
				a.lggr.Warnw("EventSync completed with errors",
					"error", err,
					"duration", elapsed)
			} else if err != nil {
				a.lggr.Warnw("EventSync timed out", "duration", elapsed)
			} else {
				a.lggr.Debugw("Event sync completed successfully",
					"duration", elapsed)
			}

			cancel()
		case <-ctx.Done():
			a.lggr.Infow("Event polling stopped")
			return
		}
	}
}

func (a *aptosChainReader) syncEvent(ctx context.Context, boundAddress aptos.AccountAddress, eventConfig *config.ChainReaderEvent, eventModuleName string) error {
	if err := a.dbStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("syncEvent: failed to ensure schema: %w", err)
	}

	eventAccountAddress, err := a.computeEventAccountAddress(boundAddress, eventConfig)
	if err != nil {
		return fmt.Errorf("syncEvent: %w", err)
	}

	eventHandle := boundAddress.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName
	eventFieldName := eventConfig.EventHandleFieldName

	latestOffset, err := a.dbStore.GetLatestOffset(ctx, eventAccountAddress.String(), eventHandle, eventFieldName)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to get latest offset: %w", err)
	}

	resource, err := a.client.AccountResource(eventAccountAddress, eventHandle)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to fetch the resource: %w", err)
	}

	creationNumber, err := crutils.ExtractEventCreationNum(resource, eventFieldName)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to extract creation_num for %s: %w", eventFieldName, err)
	}

	var batchSize uint64 = 100
	var totalProcessed int = 0

eventLoop:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			newEvents, err := a.client.EventsByCreationNumber(eventAccountAddress, creationNumber, &latestOffset, &batchSize)
			if err != nil {
				a.lggr.Errorw("syncEvent: failed to fetch new events", "error", err)
				return fmt.Errorf("syncEvent: failed to fetch events: %w", err)
			}

			if len(newEvents) == 0 {
				break eventLoop
			}

			var batchRecords []db.EventRecord
			for _, event := range newEvents {
				head, err := a.getBlockHead(event.Version)
				if err != nil {
					a.lggr.Errorw("syncEvent: failed to fetch block metadata", "version", event.Version, "error", err)
					continue
				}

				if err := crutils.RenameMapFields(event.Data, eventConfig.EventFieldRenames); err != nil {
					a.lggr.Errorw("syncEvent: failed to rename event fields", "error", err)
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
				err := a.dbStore.InsertEvents(ctx, batchRecords)
				if err != nil {
					a.lggr.Errorw("syncEvent: batch insert failed, falling back to per-event insert", "error", err)
					for _, record := range batchRecords {
						if err := a.dbStore.InsertEvents(ctx, []db.EventRecord{record}); err != nil {
							a.lggr.Errorw("syncEvent: failed to insert single event, skipping", "event", record, "error", err)
							continue
						}
						totalProcessed++
						// Advance latestOffset for each successfully inserted event
						latestOffset = record.EventOffset + 1
					}
				} else {
					totalProcessed += len(batchRecords)
					latestOffset = newEvents[len(newEvents)-1].SequenceNumber + 1
				}
				a.lggr.Debugw("syncEvent: saved batch of events",
					"batch_count", len(batchRecords),
					"total_processed", totalProcessed,
					"handle", eventHandle)
			}

			// If we received fewer events than the batch size, we're caught up
			if uint64(len(newEvents)) < batchSize {
				break eventLoop
			}
		}
	}

	return nil
}

func (a *aptosChainReader) SyncAllEvents(ctx context.Context) error {
	if a.dbStore == nil {
		return fmt.Errorf("SyncAllEvents only operates in persistent mode")
	}

	if err := a.dbStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("SyncAllEvents: failed to ensure schema: %w", err)
	}

	successCount := 0
	errorCount := 0
	var lastErr error
	for moduleKey, moduleConfig := range a.config.Modules {
		if moduleConfig.Events == nil {
			continue
		}

		boundAddress, ok := a.getModuleAddress(moduleKey)
		if !ok {
			a.lggr.Warnw("SyncAllEvents: no bound address for module", "module", moduleKey)
			continue
		}

		var eventModuleName string
		if moduleConfig.Name != "" {
			eventModuleName = moduleConfig.Name
		} else {
			eventModuleName = moduleKey
		}

		for eventKey, eventConfig := range moduleConfig.Events {
			select {
			case <-ctx.Done():
				if successCount > 0 {
					a.lggr.Infow("SyncAllEvents: interrupted, some events synced", "successCount", successCount, "errorCount", errorCount)
				}
				return ctx.Err()
			default:
				err := a.syncEvent(ctx, boundAddress, eventConfig, eventModuleName)
				if err != nil {
					errorCount++
					lastErr = fmt.Errorf("SyncAllEvents: module %s event %s: %w", moduleKey, eventKey, err)
					a.lggr.Errorw("SyncAllEvents: error syncing event", "module", moduleKey, "event", eventKey, "error", err)
				} else {
					successCount++
				}
			}
		}
	}

	if errorCount > 0 {
		a.lggr.Errorw("SyncAllEvents: completed with errors", "successCount", successCount, "errorCount", errorCount, "lastError", lastErr)
		return lastErr
	}

	a.lggr.Infow("SyncAllEvents: successfully synced all events", "count", successCount)
	return nil
}
