package logpoller

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	module_offramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_offramp/offramp"
	codec0 "github.com/smartcontractkit/chainlink-aptos/codec"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/db"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitoring/prom"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

func (l *AptosLogPoller) startTxPolling(ctx context.Context) {
	l.lggr.Infow("Transaction polling goroutine started")
	defer l.lggr.Infow("Transaction polling goroutine exited")

	if err := l.waitForInitialEvent(ctx); err != nil {
		return // Context was cancelled
	}

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

func (l *AptosLogPoller) waitForInitialEvent(ctx context.Context) error {
	const (
		moduleKey = "OffRamp"
		eventKey  = "ExecutionStateChanged"
	)

	l.lggr.Infow("Waiting for initial ExecutionStateChanged event before starting transaction polling...")

	ticker := time.NewTicker(l.config.TxPollingInterval.Duration())
	defer ticker.Stop()

	for {
		eventAccountAddress, eventHandle, eventConfig, err := l.getEventConfig(moduleKey, eventKey)
		if err != nil {
			l.lggr.Warnw("Failed to get ExecutionStateChanged event config, retrying...", "error", err)
		} else {
			events, err := l.dbStore.QueryEvents(
				ctx,
				eventAccountAddress.String(),
				eventHandle,
				eventConfig.EventHandleFieldName,
				nil,
				query.LimitAndSort{Limit: query.CountLimit(1)},
			)
			if err != nil {
				l.lggr.Warnw("Failed to query for ExecutionStateChanged events, retrying...", "error", err)
			} else if len(events) > 0 {
				l.lggr.Infow("Found initial ExecutionStateChanged event, starting tx poller.")
				return nil // Found events, proceed.
			}
		}

		select {
		case <-ticker.C:
			l.lggr.Infow("No ExecutionStateChanged events found yet, waiting...")
			continue
		case <-ctx.Done():
			l.lggr.Infow("Transaction polling stopped during initial wait.")
			return ctx.Err()
		}
	}
}

// SyncAllTransmitterTxs syncs transactions for all registered transmitters
func (l *AptosLogPoller) SyncAllTransmitterTxs(ctx context.Context) error {
	start := time.Now()

	transmitters, err := l.getTransmitters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get transmitters: %w", err)
	}

	if len(transmitters) == 0 {
		return nil
	}

	batchSize := *l.config.TxBatchSize
	var totalProcessed int

	for _, transmitter := range transmitters {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			processed, err := l.syncTransmitterTxs(ctx, transmitter, batchSize)
			if err != nil {
				l.lggr.Errorw("Failed to sync transmitter transactions",
					"transmitter", transmitter.String(), "error", err)
				continue
			}
			totalProcessed += processed
		}
	}

	elapsed := time.Since(start)
	if totalProcessed > 0 {
		l.lggr.Infow("Transaction sync completed for all transmitters",
			"totalProcessed", totalProcessed,
			"transmitterCount", len(transmitters),
			"duration", elapsed)
	} else {
		l.lggr.Debugw("Transaction sync completed for all transmitters",
			"totalProcessed", 0,
			"transmitterCount", len(transmitters),
			"duration", elapsed)
	}

	return nil
}

func (l *AptosLogPoller) syncTransmitterTxs(ctx context.Context, transmitter aptos.AccountAddress, batchSize uint64) (int, error) {
	start := time.Now()

	const (
		moduleKey = "OffRamp"
		eventKey  = "ExecutionStateChanged"
	)

	sequenceNumber, err := l.dbStore.GetTransmitterSequenceNum(ctx, transmitter.String())
	if err != nil {
		return 0, fmt.Errorf("failed to get transmitter sequence: %w", err)
	}

	l.lggr.Debugw("Starting transaction sync for transmitter",
		"transmitter", transmitter.String(),
		"fromSequence", sequenceNumber)

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
	var offRampAddress aptos.AccountAddress
	if err := offRampAddress.ParseStringRelaxed(boundAddress); err != nil {
		return 0, fmt.Errorf("parse offramp address %s: %w", boundAddress, err)
	}

	select {
	case <-ctx.Done():
		return totalProcessed, ctx.Err()
	default:
		var client aptos.AptosRpcClient
		client, err = l.getClient()
		if err != nil {
			return totalProcessed, fmt.Errorf("failed to get client: %w", err)
		}
		txns, err := client.AccountTransactions(transmitter, &sequenceNumber, &batchSize)
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

			// Skip only a Move abort the VM placed in the offramp at one of the
			// codes asserted before the receiver runs. See preDispatchAbort.
			if preDispatchAbort(userTxn.VmStatus, offRampAddress, moduleName) {
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

			prom.ReportEventsInserted(l.chainInfo, eventConfig.EventHandleFieldName, true, len(records))

			l.lggr.Debugw("Inserted synthetic ExecutionStateChanged events",
				"count", len(records), "transmitter", transmitter.String())
		}

		// Update sequence number for this transmitter
		if len(txns) > 0 {
			newSequenceNumber := sequenceNumber + uint64(len(txns))
			if err := l.dbStore.UpdateTransmitterSequence(ctx, transmitter.String(), newSequenceNumber); err != nil {
				l.lggr.Errorw("Failed to update transmitter sequence in database",
					"transmitter", transmitter.String(),
					"oldSequence", sequenceNumber,
					"newSequence", newSequenceNumber,
					"error", err)
			} else {
				l.lggr.Debugw("Updated transmitter sequence in database",
					"transmitter", transmitter.String(),
					"oldSequence", sequenceNumber,
					"newSequence", newSequenceNumber)
			}
		}

		elapsed := time.Since(start)
		l.lggr.Debugw("Finished transaction sync for transmitter",
			"transmitter", transmitter.String(),
			"processed", totalProcessed,
			"duration", elapsed)

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
	if err := codec0.DecodeAptosJsonValue(events[0].Data, &configSet); err != nil {
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
	if err := codec0.DecodeAptosJsonValue(events[0].Data, &configEvent); err != nil {
		return nil, fmt.Errorf("failed to decode SourceChainConfigSet event: %w", err)
	}

	return &configEvent.SourceChainConfig, nil
}

// moveAbortPrefix opens the status a fullnode reports for a Move abort, as in
// "Move abort in 0xa1::offramp: E_SOURCE_CHAIN_NOT_ENABLED(0x5000b)". Runtime
// failures open with "Execution failed in " and name no abort code.
const moveAbortPrefix = "Move abort in "

// preDispatchAbort reports whether vmStatus is a Move abort the VM placed in the
// bound offramp at one of the seven codes asserted before the receiver runs. A
// receiver re-entering the module can raise any other abort there.
func preDispatchAbort(vmStatus string, offRamp aptos.AccountAddress, module string) bool {
	rest, ok := strings.CutPrefix(vmStatus, moveAbortPrefix)
	if !ok {
		return false
	}
	location, codeText, ok := strings.Cut(rest, ": ")
	if !ok {
		return false
	}
	// The location is "0xADDR::module" or "0xADDR::module::function".
	segments := strings.Split(location, "::")
	if len(segments) < 2 {
		return false
	}
	var address aptos.AccountAddress
	if err := address.ParseStringRelaxed(segments[0]); err != nil {
		return false
	}
	if address != offRamp || segments[1] != module {
		return false
	}
	code, ok := abortCode(codeText)
	if !ok {
		return false
	}
	// A canonical abort code is (category << 16) + reason, where the reason is
	// the module constant and the category is the std::error constructor it is
	// raised under. invalid_argument is 0x1 and permission_denied is 0x5.
	const (
		invalidArgument  uint64 = 0x1 << 16
		invalidState     uint64 = 0x3 << 16
		permissionDenied uint64 = 0x5 << 16
	)
	switch code {
	case invalidArgument + module_offramp.E_UNKNOWN_SOURCE_CHAIN_SELECTOR,
		invalidArgument + module_offramp.E_TOKEN_DATA_MISMATCH,
		invalidArgument + module_offramp.E_ROOT_NOT_COMMITTED,
		permissionDenied + module_offramp.E_SOURCE_CHAIN_NOT_ENABLED,
		invalidState + module_offramp.E_UNSUPPORTED_TOKEN,
		invalidState + module_offramp.E_FUNGIBLE_ASSET_TYPE_MISMATCH,
		invalidState + module_offramp.E_FUNGIBLE_ASSET_AMOUNT_MISMATCH:
		return true
	}
	return false
}

// abortCode reads the abort code out of the text that follows a Move abort's
// location, as in "E_ROOT_NOT_COMMITTED(0x10009) at code offset 12".
// A module published without embedded error metadata renders no constant
// name and no parentheses, just the bare code, as in "0x10009".
func abortCode(codeText string) (uint64, bool) {
	open := strings.IndexByte(codeText, '(')
	if open < 0 {
		digits, ok := strings.CutPrefix(codeText, "0x")
		if !ok {
			return 0, false
		}
		if end := strings.IndexAny(digits, " \t"); end >= 0 {
			digits = digits[:end]
		}
		code, err := strconv.ParseUint(digits, 16, 64)
		if err != nil {
			return 0, false
		}
		return code, true
	}
	afterOpen := codeText[open+1:]
	end := strings.IndexByte(afterOpen, ')')
	if end < 0 {
		return 0, false
	}
	digits, ok := strings.CutPrefix(afterOpen[:end], "0x")
	if !ok {
		return 0, false
	}
	code, err := strconv.ParseUint(digits, 16, 64)
	if err != nil {
		return 0, false
	}
	return code, true
}
