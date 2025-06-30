package chainreader

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

func (a *aptosChainReader) startTxPolling(ctx context.Context) {
	a.lggr.Infow("Transaction polling goroutine started")
	defer a.lggr.Infow("Transaction polling goroutine exited")

	ticker := time.NewTicker(a.config.TxSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, a.config.TxSyncTimeout)
			start := time.Now()

			err := a.SyncTransmittersTxs(syncCtx)
			elapsed := time.Since(start)

			if err != nil && err != context.DeadlineExceeded {
				a.lggr.Warnw("TxSync completed with errors",
					"error", err,
					"duration", elapsed)
			} else if err != nil {
				a.lggr.Warnw("Transaction sync timed out", "duration", elapsed)
			} else {
				a.lggr.Debugw("Transaction sync completed successfully",
					"duration", elapsed)
			}

			cancel()
		case <-ctx.Done():
			a.lggr.Infow("Transaction polling stopped")
			return
		}
	}
}

func (a *aptosChainReader) SyncTransmittersTxs(ctx context.Context) error {
	transmitters, err := a.getTransmitters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transmitters: %w", err)
	}

	if len(transmitters) == 0 {
		return nil
	}

	var batchSize uint64 = 100
	var totalProcessed int

	for _, transmitter := range transmitters {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if _, exists := a.transmitters[transmitter]; !exists {
				a.lggr.Debugw("Initializing sequence number for transmitter", "transmitter", transmitter.String())
				a.transmitters[transmitter] = 0
			}

			processed, err := a.syncTransmitterTxs(ctx, transmitter, batchSize)
			if err != nil {
				a.lggr.Errorw("Failed to sync transmitter transactions",
					"transmitter", transmitter.String(), "error", err)
				continue
			}
			totalProcessed += processed
		}
	}

	if totalProcessed > 0 {
		a.lggr.Debugw("Transaction sync completed", "totalProcessed", totalProcessed)
	}

	return nil
}

func (a *aptosChainReader) syncTransmitterTxs(ctx context.Context, transmitter aptos.AccountAddress, batchSize uint64) (int, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "ExecutionStateChanged"
	)

	sequenceNumber := a.transmitters[transmitter]
	totalProcessed := 0

	eventAccountAddress, eventHandle, eventConfig, err := a.getEventConfig(moduleKey, eventKey)
	if err != nil {
		return 0, fmt.Errorf("failed to get ExecutionStateChanged event config: %w", err)
	}

	parts := strings.Split(eventHandle, "::")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid event handle format: %s", eventHandle)
	}

	boundAddress := parts[0]
	moduleName := parts[1]
	expectedFunction := fmt.Sprintf("%s::%s::execute", boundAddress, moduleName)
	// if the vmStatus of the failed tx contains the following,
	// we ignore the tx because if was reverted before the receiver
	ignoredVmError := fmt.Sprintf("%s::%s", boundAddress, moduleName)

	select {
	case <-ctx.Done():
		return totalProcessed, ctx.Err()
	default:
		txns, err := a.client.AccountTransactions(transmitter, &sequenceNumber, &batchSize)
		if err != nil {
			return totalProcessed, fmt.Errorf("failed to fetch transactions: %w", err)
		}

		if len(txns) == 0 {
			return totalProcessed, nil
		}

		var records []db.EventRecord
		for _, txn := range txns {
			userTxn, err := txn.UserTransaction()
			if err != nil {
				a.lggr.Errorw("Failed to get user transaction",
					"transmitter", transmitter.String(), "error", err)
				continue
			}

			if userTxn.Success {
				a.lggr.Debugw("Skipping successful transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			a.lggr.Infow("Found failed transaction", "transmitter", transmitter.String(),
				"sequenceNumber", userTxn.SequenceNumber, "version", userTxn.Version, "vmStatus", userTxn.VmStatus)

			payload := userTxn.Payload
			if payload.Type != api.TransactionPayloadVariantEntryFunction {
				a.lggr.Debugw("Skipping non-entry function transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			entryFunc, ok := payload.Inner.(*api.TransactionPayloadEntryFunction)
			if !ok {
				a.lggr.Errorw("Failed to cast payload to EntryFunction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			if entryFunc.Function != expectedFunction {
				a.lggr.Debugw("Skipping transaction with different function",
					"transmitter", transmitter.String(), "function", entryFunc.Function)
				continue
			}

			if strings.Contains(userTxn.VmStatus, ignoredVmError) {
				a.lggr.Debugw("Skipping non-receiver originated transaction", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber, "vmStatus", userTxn.VmStatus)
				continue
			}

			if len(entryFunc.Arguments) != 2 {
				a.lggr.Errorw("Unexpected number of arguments in transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber,
					"expected", 2, "got", len(entryFunc.Arguments))
				continue
			}

			reportStr, ok := entryFunc.Arguments[1].(string)
			if !ok {
				a.lggr.Errorw("Expected report to be a hex string", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			report, err := utils.DecodeHexRelaxed(reportStr)
			if err != nil {
				a.lggr.Errorw("failed to cast report to []byte", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			execReport, err := crutils.DeserializeExecutionReport(report)
			if err != nil {
				a.lggr.Errorw("Failed to deserialize execution report",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber, "error", err)
				continue
			}

			sourceChainSelector := execReport.Message.Header.SourceChainSelector
			sourceChainConfig, err := a.getSourceChainConfig(ctx, sourceChainSelector)
			if err != nil {
				a.lggr.Errorw("Failed to get source chain config",
					"transmitter", transmitter.String(), "sourceChainSelector", sourceChainSelector, "error", err)
				continue
			}

			if sourceChainConfig == nil {
				a.lggr.Debugw("No source chain config found for selector",
					"transmitter", transmitter.String(), "sourceChainSelector", sourceChainSelector)
				continue
			}

			hasher := crutils.NewMessageHasherV1(a.lggr)
			messageHash, err := hasher.Hash(ctx, execReport, sourceChainConfig.OnRamp)
			if err != nil {
				a.lggr.Errorw("Failed to calculate message hash",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber, "error", err)
				continue
			}

			// Create synthetic ExecutionStateChanged event
			// The fields map one-to-one the onchain event
			executionStateChanged := map[string]any{
				"source_chain_selector": fmt.Sprintf("%d", sourceChainSelector),
				"sequence_number":       fmt.Sprintf("%d", execReport.Message.Header.SequenceNumber),
				"message_id":            "0x" + hex.EncodeToString(execReport.Message.Header.MessageID),
				"message_hash":          "0x" + hex.EncodeToString(messageHash[:]),
				"state":                 uint8(3), // 3 = FAILURE
			}

			head, err := a.getBlockHead(userTxn.Version)
			if err != nil {
				a.lggr.Errorw("Failed to fetch block metadata", "version", userTxn.Version, "error", err)
				continue
			}

			if eventConfig.EventFieldRenames != nil {
				if err := crutils.RenameMapFields(executionStateChanged, eventConfig.EventFieldRenames); err != nil {
					a.lggr.Errorw("Failed to rename synthetic event fields", "error", err)
					continue
				}
			}

			record := db.EventRecord{
				EventAccountAddress: eventAccountAddress.String(),
				EventHandle:         eventHandle,
				EventFieldName:      eventConfig.EventHandleFieldName,
				// Synthetic events have an offset of zero, since there won't be a duplicate event of the same type inside the same tx
				EventOffset:    0,
				TxVersion:      userTxn.Version,
				BlockHeight:    head.Height,
				BlockHash:      head.Hash,
				BlockTimestamp: head.Timestamp,
				Data:           executionStateChanged,
			}

			records = append(records, record)
			totalProcessed++
		}

		if len(records) > 0 {
			if err := a.dbStore.InsertEvents(ctx, records); err != nil {
				a.lggr.Errorw("Failed to insert synthetic ExecutionStateChanged events", "error", err)
				return totalProcessed, fmt.Errorf("failed to insert events: %w", err)
			}

			a.lggr.Debugw("Inserted synthetic ExecutionStateChanged events",
				"count", len(records), "transmitter", transmitter.String())
		}

		sequenceNumber += uint64(len(txns))
		a.transmitters[transmitter] = sequenceNumber

		return totalProcessed, nil
	}
}

func (a *aptosChainReader) getTransmitters(ctx context.Context) ([]aptos.AccountAddress, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "OCRConfigSet"
	)

	eventAccountAddress, eventHandle, eventConfig, err := a.getEventConfig(moduleKey, eventKey)
	if err != nil {
		a.lggr.Errorw("Failed to get OCRConfigSet event config", "error", err)
		return nil, err
	}

	events, err := a.dbStore.QueryEvents(
		ctx,
		eventAccountAddress.String(),
		eventHandle,
		eventConfig.EventHandleFieldName,
		nil,
		query.LimitAndSort{
			Limit: query.CountLimit(1),
			SortBy: []query.SortBy{
				query.NewSortBySequence(query.Desc),
			},
		},
	)

	if err != nil {
		a.lggr.Errorw("Failed to query OCRConfigSet events", "error", err)
		return nil, err
	}

	if len(events) == 0 {
		a.lggr.Warnw("No OCRConfigSet events found")
		return nil, nil
	}

	var configSet crutils.ConfigSet
	if err := codec.DecodeAptosJsonValue(events[0].Data, &configSet); err != nil {
		a.lggr.Errorw("Failed to decode ConfigSet event", "error", err)
		return nil, fmt.Errorf("failed to decode ConfigSet event: %w", err)
	}

	transmitters := configSet.Transmitters
	if len(transmitters) == 0 {
		a.lggr.Warnw("No transmitters found in OCRConfigSet event")
		return nil, nil
	}

	a.lggr.Infow("Found transmitters in OCRConfigSet event", "count", len(transmitters))
	return transmitters, nil
}

func (a *aptosChainReader) getSourceChainConfig(ctx context.Context, sourceChainSelector uint64) (*crutils.SourceChainConfig, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "SourceChainConfigSet"
		selector  = "SourceChainSelector"
	)

	eventAccountAddress, eventHandle, eventConfig, err := a.getEventConfig(moduleKey, eventKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get SourceChainConfigSet event config: %w", err)
	}

	filter := []query.Expression{
		query.Comparator(selector,
			primitives.ValueComparator{Value: sourceChainSelector, Operator: primitives.Eq},
		),
	}

	events, err := a.dbStore.QueryEvents(
		ctx,
		eventAccountAddress.String(),
		eventHandle,
		eventConfig.EventHandleFieldName,
		filter,
		query.LimitAndSort{
			Limit: query.CountLimit(1),
			SortBy: []query.SortBy{
				query.NewSortBySequence(query.Desc),
			},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to query SourceChainConfigSet event: %w", err)
	}

	if len(events) == 0 {
		a.lggr.Debugw("No SourceChainConfigSet event found", "sourceChainSelector", sourceChainSelector)
		return nil, nil
	}

	var configEvent crutils.SourceChainConfigSet
	if err := codec.DecodeAptosJsonValue(events[0].Data, &configEvent); err != nil {
		return nil, fmt.Errorf("failed to decode SourceChainConfigSet event: %w", err)
	}

	return &configEvent.SourceChainConfig, nil
}
