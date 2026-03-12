package logpoller

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
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
	for k, v := range l.modules {
		modulesCopy[k] = v
	}
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

func (l *AptosLogPoller) syncEvent(ctx context.Context, boundAddress aptos.AccountAddress, eventConfig *config.ChainReaderEvent, eventModuleName string) error {
	start := time.Now()

	eventAccountAddress, err := l.computeEventAccountAddress(boundAddress, eventConfig)
	if err != nil {
		return fmt.Errorf("syncEvent: %w", err)
	}

	eventHandle := boundAddress.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName
	eventFieldName := eventConfig.EventHandleFieldName

	latestOffset, err := l.dbStore.GetLatestOffset(ctx, eventAccountAddress.String(), eventHandle, eventFieldName)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to get latest offset: %w", err)
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
				l.lggr.Errorw("syncEvent: failed to fetch new events", "error", err)
				return fmt.Errorf("syncEvent: failed to fetch events: %w", err)
			}

			if len(events) == 0 {
				break eventLoop
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
				if err := l.dbStore.InsertEvents(ctx, batchRecords); err != nil {
					return fmt.Errorf("syncEvent: failed to insert batch of events: %w", err)
				}

				prom.ReportEventsInserted(l.chainInfo, eventFieldName, false, len(batchRecords))

				totalProcessed += len(batchRecords)
				l.lggr.Debugw("syncEvent: saved batch of events",
					"batch_count", len(batchRecords),
					"total_processed", totalProcessed,
					"handle", eventHandle,
					"field", eventFieldName)
			}

			latestOffset = events[len(events)-1].SequenceNumber + 1

			// If we received fewer events than the batch size, we're caught up
			if uint64(len(events)) < batchSize {
				break eventLoop
			}
		}
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

func (l *AptosLogPoller) computeEventAccountAddress(boundAddress aptos.AccountAddress, eventConfig *config.ChainReaderEvent) (aptos.AccountAddress, error) {
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
