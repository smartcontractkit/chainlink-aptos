package chainreader

import (
	"context"
	"fmt"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/txpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

func (a *aptosChainReader) startTxPolling(ctx context.Context) {
	ticker := time.NewTicker(a.config.TxSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, a.config.TxSyncTimeout)
			start := time.Now()

			err := a.SyncTransmitterTransactions(syncCtx)
			elapsed := time.Since(start)

			if err != nil && err != context.DeadlineExceeded {
				a.logger.Warnw("Txsync completed with errors",
					"error", err,
					"duration", elapsed)
			} else if err != nil {
				a.logger.Warnw("Transaction sync timed out", "duration", elapsed)
			} else {
				a.logger.Debugw("Transaction sync completed successfully",
					"duration", elapsed)
			}

			cancel()
		case <-ctx.Done():
			a.logger.Infow("Transaction polling stopped")
			return
		}
	}
}

func (a *aptosChainReader) SyncTransmitterTransactions(ctx context.Context) error {
	if a.dbStore == nil {
		return fmt.Errorf("SyncTransmitterTransactions only operates in persistent mode")
	}

	if err := a.dbStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("failed to ensure schema: %w", err)
	}

	// todo: import consts from somewhere?
	const (
		ocrModuleKey      = "OffRamp"
		configSetEventKey = "OCRConfigSet"
	)

	moduleConfig, ok := a.config.Modules[ocrModuleKey]
	if !ok {
		a.logger.Warnw("SyncTransmitterTransactions: no module config found", "moduleKey", ocrModuleKey)
		return nil
	}

	boundAddress, ok := a.moduleAddresses[ocrModuleKey]
	if !ok {
		a.logger.Warnw("SyncTransmitterTransactions: no bound address for module", "moduleKey", ocrModuleKey)
		return nil
	}

	configSetEvent, ok := moduleConfig.Events[configSetEventKey]
	if !ok {
		a.logger.Warnw("SyncTransmitterTransactions: no event config found", "moduleKey", ocrModuleKey, "eventKey", configSetEventKey)
		return nil
	}

	moduleName := moduleConfig.Name
	if moduleName == "" {
		moduleName = ocrModuleKey
	}

	eventAccountAddress, err := a.computeEventAccountAddress(boundAddress, configSetEvent)
	if err != nil {
		a.logger.Errorw("Failed to compute event account address",
			"moduleKey", ocrModuleKey,
			"eventKey", configSetEventKey,
			"error", err)
		return err
	}

	eventHandle := boundAddress.String() + "::" + moduleName + "::" + configSetEvent.EventHandleStructName
	eventFieldName := configSetEvent.EventHandleFieldName

	events, err := a.dbStore.QueryEvents(
		ctx,
		eventAccountAddress.String(),
		eventHandle,
		eventFieldName,
		nil,
		query.LimitAndSort{
			Limit: query.CountLimit(1),
			SortBy: []query.SortBy{
				query.NewSortBySequence(query.Desc),
			},
		},
	)

	if err != nil {
		a.logger.Errorw("Failed to query OCRConfigSet events", "error", err)
		return err
	}

	if len(events) == 0 {
		a.logger.Errorw("No OCRConfigSet events found")
		return nil
	}

	var event txpoller.ConfigSet
	if err := codec.DecodeAptosJsonValue(events[0].Data, &event); err != nil {
		a.logger.Errorw("Failed to decode ConfigSet event", "error", err)
		return fmt.Errorf("failed to decode ConfigSet event: %w", err)
	}

	if len(event.Transmitters) == 0 {
		a.logger.Warnw("No transmitters found in OCRConfigSet event")
		return nil
	}

	a.logger.Infow("Found transmitters in OCRConfigSet event", "count", len(event.Transmitters))

	return nil
}
