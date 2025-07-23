package logpoller

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

func (l *AptosLogPoller) startTxPolling(ctx context.Context) {
	l.lggr.Infow("Transaction polling goroutine started")
	defer l.lggr.Infow("Transaction polling goroutine exited")

	ticker := time.NewTicker(l.config.TxPollingInterval.Duration())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			syncCtx, cancel := context.WithTimeout(ctx, l.config.PollTimeout.Duration())
			start := time.Now()

			err := l.SyncAllTransmitterTxs(syncCtx)
			elapsed := time.Since(start)

			if err != nil && err != context.DeadlineExceeded {
				l.lggr.Warnw("TxSync completed with errors",
					"error", err,
					"duration", elapsed)
			} else if err != nil {
				l.lggr.Warnw("Transaction sync timed out", "duration", elapsed)
			} else {
				l.lggr.Debugw("Transaction sync completed successfully",
					"duration", elapsed)
			}

			cancel()
		case <-ctx.Done():
			l.lggr.Infow("Transaction polling stopped")
			return
		}
	}
}

// SyncAllTransmitterTxs syncs transactions for all registered transmitters
func (l *AptosLogPoller) SyncAllTransmitterTxs(ctx context.Context) error {
	transmitters, err := l.getTransmitters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transmitters: %w", err)
	}

	if len(transmitters) == 0 {
		return nil
	}

	batchSize := l.config.TxBatchSize
	var totalProcessed int

	for _, transmitter := range transmitters {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			l.mu.Lock()
			_, exists := l.transmitters[transmitter]
			if !exists {
				l.lggr.Debugw("Initializing sequence number for transmitter", "transmitter", transmitter.String())
				l.transmitters[transmitter] = 0
			}
			l.mu.Unlock()

			processed, err := l.syncTransmitterTxs(ctx, transmitter, batchSize)
			if err != nil {
				l.lggr.Errorw("Failed to sync transmitter transactions",
					"transmitter", transmitter.String(), "error", err)
				continue
			}
			totalProcessed += processed
		}
	}

	if totalProcessed > 0 {
		l.lggr.Debugw("Transaction sync completed", "totalProcessed", totalProcessed)
	}

	return nil
}

func (l *AptosLogPoller) syncTransmitterTxs(ctx context.Context, transmitter aptos.AccountAddress, batchSize uint64) (int, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "ExecutionStateChanged"
	)

	l.mu.RLock()
	sequenceNumber := l.transmitters[transmitter]
	l.mu.RUnlock()

	totalProcessed := 0

	eventAccountAddress, eventHandle, eventConfig, err := l.getEventConfig(moduleKey, eventKey)
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
	// we ignore the tx because it was reverted before the receiver
	ignoredVmError := fmt.Sprintf("%s::%s", boundAddress, moduleName)

	select {
	case <-ctx.Done():
		return totalProcessed, ctx.Err()
	default:
		txns, err := l.client.AccountTransactions(transmitter, &sequenceNumber, &batchSize)
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
				l.lggr.Errorw("Failed to get user transaction",
					"transmitter", transmitter.String(), "error", err)
				continue
			}

			// Skip successful transactions - we only care about failures
			if userTxn.Success {
				l.lggr.Debugw("Skipping successful transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			l.lggr.Infow("Found failed transaction", "transmitter", transmitter.String(),
				"sequenceNumber", userTxn.SequenceNumber, "version", userTxn.Version, "vmStatus", userTxn.VmStatus)

			// Check if this is an entry function transaction
			payload := userTxn.Payload
			if payload.Type != api.TransactionPayloadVariantEntryFunction {
				l.lggr.Debugw("Skipping non-entry function transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			entryFunc, ok := payload.Inner.(*api.TransactionPayloadEntryFunction)
			if !ok {
				l.lggr.Errorw("Failed to cast payload to EntryFunction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			// Check if this transaction is calling the expected function
			if entryFunc.Function != expectedFunction {
				l.lggr.Debugw("Skipping transaction with different function",
					"transmitter", transmitter.String(), "function", entryFunc.Function)
				continue
			}

			// Skip if error is from the module itself
			if strings.Contains(userTxn.VmStatus, ignoredVmError) {
				l.lggr.Debugw("Skipping non-receiver originated transaction", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber, "vmStatus", userTxn.VmStatus)
				continue
			}

			// Check arguments
			if len(entryFunc.Arguments) != 2 {
				l.lggr.Errorw("Unexpected number of arguments in transaction",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber,
					"expected", 2, "got", len(entryFunc.Arguments))
				continue
			}

			// Get the report from arguments
			reportStr, ok := entryFunc.Arguments[1].(string)
			if !ok {
				l.lggr.Errorw("Expected report to be a hex string", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			report, err := utils.DecodeHexRelaxed(reportStr)
			if err != nil {
				l.lggr.Errorw("failed to decode report hex", "transmitter", transmitter.String(),
					"sequenceNumber", userTxn.SequenceNumber)
				continue
			}

			execReport, err := crutils.DeserializeExecutionReport(report)
			if err != nil {
				l.lggr.Errorw("Failed to deserialize execution report",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber, "error", err)
				continue
			}

			// Get source chain config
			sourceChainSelector := execReport.Message.Header.SourceChainSelector
			sourceChainConfig, err := l.getSourceChainConfig(ctx, sourceChainSelector)
			if err != nil {
				l.lggr.Errorw("Failed to get source chain config",
					"transmitter", transmitter.String(), "sourceChainSelector", sourceChainSelector, "error", err)
				continue
			}

			if sourceChainConfig == nil {
				l.lggr.Debugw("No source chain config found for selector",
					"transmitter", transmitter.String(), "sourceChainSelector", sourceChainSelector)
				continue
			}

			// Calculate message hash
			hasher := crutils.NewMessageHasherV1(l.lggr)
			messageHash, err := hasher.Hash(ctx, execReport, sourceChainConfig.OnRamp)
			if err != nil {
				l.lggr.Errorw("Failed to calculate message hash",
					"transmitter", transmitter.String(), "sequenceNumber", userTxn.SequenceNumber, "error", err)
				continue
			}

			// Create synthetic ExecutionStateChanged event
			executionStateChanged := map[string]any{
				"source_chain_selector": fmt.Sprintf("%d", sourceChainSelector),
				"sequence_number":       fmt.Sprintf("%d", execReport.Message.Header.SequenceNumber),
				"message_id":            "0x" + hex.EncodeToString(execReport.Message.Header.MessageID),
				"message_hash":          "0x" + hex.EncodeToString(messageHash[:]),
				"state":                 uint8(3), // 3 = FAILURE
			}

			head, err := l.getBlockHead(userTxn.Version)
			if err != nil {
				l.lggr.Errorw("Failed to fetch block metadata", "version", userTxn.Version, "error", err)
				continue
			}

			if eventConfig.EventFieldRenames != nil {
				if err := crutils.RenameMapFields(executionStateChanged, eventConfig.EventFieldRenames); err != nil {
					l.lggr.Errorw("Failed to rename synthetic event fields", "error", err)
					continue
				}
			}

			record := db.EventRecord{
				EventAccountAddress: eventAccountAddress.String(),
				EventHandle:         eventHandle,
				EventFieldName:      eventConfig.EventHandleFieldName,
				// Synthetic events have offset 0
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
			if err := l.dbStore.InsertEvents(ctx, records); err != nil {
				l.lggr.Errorw("Failed to insert synthetic ExecutionStateChanged events", "error", err)
				return totalProcessed, fmt.Errorf("failed to insert events: %w", err)
			}

			l.lggr.Debugw("Inserted synthetic ExecutionStateChanged events",
				"count", len(records), "transmitter", transmitter.String())
		}

		// Update sequence number for this transmitter
		l.mu.Lock()
		l.transmitters[transmitter] = sequenceNumber + uint64(len(txns))
		l.mu.Unlock()

		return totalProcessed, nil
	}
}

func (l *AptosLogPoller) getTransmitters(ctx context.Context) ([]aptos.AccountAddress, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "OCRConfigSet"
	)

	eventAccountAddress, eventHandle, eventConfig, err := l.getEventConfig(moduleKey, eventKey)
	if err != nil {
		l.lggr.Errorw("Failed to get OCRConfigSet event config", "error", err)
		return nil, err
	}

	// Query for the latest OCRConfigSet event
	events, err := l.dbStore.QueryEvents(
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
		l.lggr.Errorw("Failed to query OCRConfigSet events", "error", err)
		return nil, err
	}

	if len(events) == 0 {
		l.lggr.Warnw("No OCRConfigSet events found")
		return nil, nil
	}

	// Decode the config set event to get transmitters
	var configSet crutils.ConfigSet
	if err := codec.DecodeAptosJsonValue(events[0].Data, &configSet); err != nil {
		l.lggr.Errorw("Failed to decode ConfigSet event", "error", err)
		return nil, fmt.Errorf("failed to decode ConfigSet event: %w", err)
	}

	transmitters := configSet.Transmitters
	if len(transmitters) == 0 {
		l.lggr.Warnw("No transmitters found in OCRConfigSet event")
		return nil, nil
	}

	l.lggr.Infow("Found transmitters in OCRConfigSet event", "count", len(transmitters))
	return transmitters, nil
}

func (l *AptosLogPoller) getSourceChainConfig(ctx context.Context, sourceChainSelector uint64) (*crutils.SourceChainConfig, error) {
	const (
		moduleKey = "OffRamp"
		eventKey  = "SourceChainConfigSet"
		selector  = "SourceChainSelector"
	)

	eventAccountAddress, eventHandle, eventConfig, err := l.getEventConfig(moduleKey, eventKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get SourceChainConfigSet event config: %w", err)
	}

	filter := []query.Expression{
		query.Comparator(selector,
			primitives.ValueComparator{Value: fmt.Sprintf("%d", sourceChainSelector), Operator: primitives.Eq},
		),
	}

	events, err := l.dbStore.QueryEvents(
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
		l.lggr.Debugw("No SourceChainConfigSet event found", "sourceChainSelector", sourceChainSelector)
		return nil, nil
	}

	var configEvent crutils.SourceChainConfigSet
	if err := codec.DecodeAptosJsonValue(events[0].Data, &configEvent); err != nil {
		return nil, fmt.Errorf("failed to decode SourceChainConfigSet event: %w", err)
	}

	return &configEvent.SourceChainConfig, nil
}
