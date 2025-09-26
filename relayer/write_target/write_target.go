// NOTE: file is based on the generic write target capability, but we're slightly modifying it until the two implementations can be merged
// in particular, we need to invert the calling flow for Aptos so receiver is the entrypoint
package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/report/platform"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"

	wt "github.com/smartcontractkit/chainlink-aptos/relayer/monitoring/pb/platform/write-target"
	rtypes "github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

var (
	_ capabilities.TargetCapability = &writeTarget{}
)

// required field of target's config in the workflow spec
const (
	CapabilityName = "write"

	// Input keys
	KeySignedReport = "signed_report"

	// Static contract info
	ContractName                            = "forwarder"
	ContractMethodName_report               = "report"
	ContractMethodName_getTransmissionState = "getTransmissionState"
	ContractMethodName_getTransmitter       = "getTransmitter"
)

type chainService interface {
	LatestHead(ctx context.Context) (commontypes.Head, error)
}

type contractReader interface {
	GetLatestValue(ctx context.Context, readIdentifier string, confidenceLevel primitives.ConfidenceLevel, params, returnVal any) error
}

type contractWriter interface {
	commontypes.ContractWriter
	GetTransactionFee(ctx context.Context, transactionID string) (decimal.Decimal, error)
}

type writeTarget struct {
	capabilities.CapabilityInfo

	config    Config
	chainInfo rtypes.ChainInfo

	lggr logger.Logger
	// Local beholder client, also hosting the protobuf emitter
	beholder *monitor.BeholderClient

	cs               chainService
	cr               contractReader
	cw               contractWriter
	configValidateFn func(config ReqConfig) error
	decodeReport     func(report []byte, metadata capabilities.RequestMetadata) (*platform.Report, error)

	nodeAddress      string
	forwarderAddress string
}

type WriteTargetOpts struct {
	ID string

	// toml: [<CHAIN>.WriteTargetCap]
	Config Config
	// ChainInfo contains the chain information (used as execution context)
	// TODO: simplify by passing via ChainService.GetChainStatus fn
	ChainInfo rtypes.ChainInfo

	Logger   logger.Logger
	Beholder *monitor.BeholderClient

	ChainService     chainService
	ContractReader   contractReader
	ChainWriter      contractWriter
	ConfigValidateFn func(config ReqConfig) error

	NodeAddress      string
	ForwarderAddress string
}

// Capability-specific configuration
type ReqConfig struct {
	Address string
}

type TransmissionState struct {
	Transmitter string
	Success     bool
}

// NewWriteTargetID returns the capability ID for the write target
func NewWriteTargetID(chainFamilyName, networkName, chainID, tag, version string) (string, error) {
	// Input args should not be empty
	if chainFamilyName == "" || version == "" {
		return "", fmt.Errorf("invalid input: chainFamilyName, and version must not be empty")
	}

	// Network ID: network name is optional, if not provided, use the chain ID
	networkID := networkName
	if networkID == "" && chainID == "" {
		return "", fmt.Errorf("invalid input: networkName or chainID must not be empty")
	}
	if networkID == "" || networkID == "unknown" {
		networkID = chainID
	}

	id := fmt.Sprintf("%s_%s-%s", CapabilityName, chainFamilyName, networkID)
	if tag != "" {
		id += ":" + tag
	}

	return id + "@" + version, nil
}

// TODO: opts.Config input is not validated for sanity
func NewWriteTarget(opts WriteTargetOpts) capabilities.TargetCapability {
	return newWriteTarget(opts)
}

func newWriteTarget(opts WriteTargetOpts) *writeTarget {
	capInfo := capabilities.MustNewCapabilityInfo(opts.ID, capabilities.CapabilityTypeTarget, CapabilityName)

	return &writeTarget{
		capInfo,
		opts.Config,
		opts.ChainInfo,
		opts.Logger,
		opts.Beholder,
		opts.ChainService,
		opts.ContractReader,
		opts.ChainWriter,
		opts.ConfigValidateFn,
		decodeReport,
		opts.NodeAddress,
		opts.ForwarderAddress,
	}
}

func success() capabilities.CapabilityResponse {
	return capabilities.CapabilityResponse{}
}

func (c *writeTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	// Take the local timestamp
	tsStart := time.Now().UnixMilli()

	// Trace the execution
	attrs := c.traceAttributes(request.Metadata.WorkflowExecutionID)
	_, span := c.beholder.Tracer.Start(ctx, "Execute", trace.WithAttributes(attrs...))
	defer span.End()

	// Notice: error skipped as implementation always returns nil
	capInfo, _ := c.Info(ctx)

	c.lggr.Debugw("Execute", "request", request, "capInfo", capInfo)

	// Helper to keep track of the request info
	info := &requestInfo{
		tsStart:   tsStart,
		node:      c.nodeAddress,
		forwarder: c.forwarderAddress,
		receiver:  "N/A",
		request:   request,
		reportInfo: &reportInfo{
			reportContext: nil,
			report:        nil,
			signersNum:    0, // N/A
			reportID:      0, // N/A
		},
		reportTransmissionState: nil,
	}
	// Helper to build monitoring (Beholder) messages
	builder := NewMessageBuilder(c.chainInfo, capInfo)

	if request.Config == nil {
		msg := builder.buildWriteError(info, 0, "empty request config", "empty request config")
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Parse the request (WT-specific) config
	var reqConfig ReqConfig
	err := request.Config.UnwrapTo(&reqConfig)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to parse config", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Validate the config
	err = c.configValidateFn(reqConfig)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to validate config", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Source the receiver address from the config
	info.receiver = reqConfig.Address

	if request.Inputs == nil {
		msg := builder.buildWriteError(info, 0, "empty request inputs", "empty request inputs")
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Source the signed report from the request
	signedReport, ok := request.Inputs.Underlying[KeySignedReport]
	if !ok {
		cause := fmt.Sprintf("input missing required field: '%s'", KeySignedReport)
		msg := builder.buildWriteError(info, 0, "failed to source the signed report", cause)
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Decode the signed report
	inputs := types.SignedReport{}
	if err = signedReport.UnwrapTo(&inputs); err != nil {
		msg := builder.buildWriteError(info, 0, "failed to parse signed report", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Source the report ID from the input
	info.reportInfo.reportID = binary.BigEndian.Uint16(inputs.ID)

	// Decode the workflow execution ID
	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to decode the workflow execution ID", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteInitiated(info))

	// Check whether the report is valid (e.g., not empty)
	if len(inputs.Report) == 0 {
		// We received any empty report -- this means we should skip transmission.
		_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSkipped(info, "empty report"))
		return success(), nil
	}

	// Update the info with the report info
	info.reportInfo = &reportInfo{
		reportID:      info.reportInfo.reportID,
		reportContext: inputs.Context,
		report:        inputs.Report,
		signersNum:    uint32(len(inputs.Signatures)),
	}

	// Decode the report
	reportDecoded, err := c.decodeReport(inputs.Report, request.Metadata)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "report is invalid", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	// Check whether the report was already transmitted on chain
	binding := commontypes.BoundContract{
		Address: info.forwarder,
		Name:    ContractName,
	}
	queryInputs := struct {
		Receiver            string
		WorkflowExecutionID []byte
		ReportID            uint16
	}{
		Receiver:            info.receiver,
		WorkflowExecutionID: rawExecutionID,
		ReportID:            info.reportInfo.reportID,
	}

	// Fetch the latest head from the chain (timestamp), retry with a default backoff strategy
	ctx = context.WithValue(ctx, utils.CtxKeyTracingID, info.request.Metadata.WorkflowExecutionID)
	head, err := utils.WithRetry(ctx, c.lggr, c.cs.LatestHead)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to fetch the latest head", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	c.lggr.Debugw("non-empty valid report",
		"reportID", info.reportInfo.reportID,
		"report", "0x"+hex.EncodeToString(inputs.Report),
		"reportLen", len(inputs.Report),
		"reportDecoded", reportDecoded,
		"reportContext", "0x"+hex.EncodeToString(inputs.Context),
		"reportContextLen", len(inputs.Context),
		"signaturesLen", len(inputs.Signatures),
		"executionID", request.Metadata.WorkflowExecutionID,
	)

	c.lggr.Debugw("querying [TransmissionState]", "binding", binding, "queryInputs", queryInputs)

	// Notice: if not confirmed the report is published yet, we're expected to submit the report on-chain (might be
	// competing with other nodes). We want to confirm this report was accepted and finalized eventually, or timeout
	// and emit an error - we store the confirm query

	// Helper to query the chain for the transmission state
	// TODO: it's unclear how to source the TransmissionState via an abstracted CR API call
	// Notice: this function is Aptos chain-specific (logic needs to be hidden behind the CR API call)
	query := func(ctx context.Context) (*TransmissionState, error) {
		// Check if transmission state exists
		var transmitted bool
		readTransmissionState := binding.ReadIdentifier(ContractMethodName_getTransmissionState)
		err := c.cr.GetLatestValue(ctx, readTransmissionState, primitives.Unconfirmed, queryInputs, &transmitted)
		if err != nil {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmissionState]: %w", err)
		}

		c.lggr.Debugw("[forwarder.getTransmissionState] call output", "transmitted", transmitted)

		// nil state means the report was not transmitted yet
		if !transmitted {
			return nil, nil
		}

		// Fetch the transmitter address from the chain (decode output type)
		// Notice: here we leak an Apots specific type and implementation - Option<string> (not-portable, not chain-agnostic)
		var transmitterAddr struct {
			Vec []string
		}
		readTransmitter := binding.ReadIdentifier(ContractMethodName_getTransmitter)
		err = c.cr.GetLatestValue(ctx, readTransmitter, primitives.Unconfirmed, queryInputs, &transmitterAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: %w", err)
		}

		c.lggr.Debugw("[forwarder.getTransmitter] call output", "transmitterAddr", transmitterAddr)

		if len(transmitterAddr.Vec) == 0 {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: unexpected empty result")
		}

		// Notice: more Apots-specific logic to decode the transmitter address (not portable)
		// Needs to be moved to CR codec (decoder), same as for Option<> type decoding above
		address, err := utils.HexAddressToAddress(transmitterAddr.Vec[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse transmitter address: %w", err)
		}

		return &TransmissionState{Transmitter: address.String(), Success: true}, nil
	}

	// Fetch the transmission state, retry with a default backoff strategy
	state, err := utils.WithRetry(ctx, c.lggr, query)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to fetch [TransmissionState]", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	if state != nil {
		// Source the transmitter address from the on-chain state
		info.reportTransmissionState = state

		_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(info, head))
		return success(), nil
	}

	c.lggr.Infow("on-chain report check done - attempting to push to txmgr",
		"reportID", info.reportInfo.reportID,
		"reportLen", len(inputs.Report),
		"reportContextLen", len(inputs.Context),
		"signaturesLen", len(inputs.Signatures),
		"executionID", request.Metadata.WorkflowExecutionID,
	)

	txID, err := uuid.NewUUID() // NOTE: CW expects us to generate an ID, rather than return one
	if err != nil {
		// This should never happen
		return capabilities.CapabilityResponse{}, err
	}

	// Note: The codec that ChainWriter uses to encode the parameters for the contract ABI cannot handle
	// `nil` values, including for slices. Until the bug is fixed we need to ensure that there are no
	// `nil` values passed in the request.
	req := struct {
		Receiver   string
		RawReport  []byte
		Signatures [][]byte
	}{
		Receiver:   info.receiver,
		RawReport:  append(inputs.Context, inputs.Report...),
		Signatures: inputs.Signatures,
	}

	if req.RawReport == nil {
		req.RawReport = make([]byte, 0)
	}

	if req.Signatures == nil {
		req.Signatures = make([][]byte, 0)
	}

	// Submit the transaction
	meta := commontypes.TxMeta{WorkflowExecutionID: &request.Metadata.WorkflowExecutionID}
	value := big.NewInt(0)
	err = c.cw.SubmitTransaction(ctx, ContractName, ContractMethodName_report, req, txID.String(), info.forwarder, &meta, value)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to invoke [forwarder.report]", err.Error())
		return capabilities.CapabilityResponse{}, c.asEmittedError(ctx, msg)
	}

	c.lggr.Debugw("Transaction submitted", "request", request, "transaction-id", txID)
	_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSent(info, head, txID.String()))

	// TODO: implement a background WriteTxConfirmer to periodically source new events/transactions,
	// relevant to this forwarder), and emit write-tx-accepted/confirmed events.
	err = c.acceptAndConfirmWrite(ctx, *info, txID, query)
	if err != nil {
		return capabilities.CapabilityResponse{}, err
	}

	// Get the transaction fee
	fee, err := c.cw.GetTransactionFee(ctx, txID.String())
	if err != nil {
		c.lggr.Errorw("failed to get transaction fee", "error", err)
		return success(), nil
	}

	return capabilities.CapabilityResponse{
		Metadata: capabilities.ResponseMetadata{
			Metering: []capabilities.MeteringNodeDetail{
				{
					// Peer2PeerID from remote peers is ignored by engine
					SpendUnit:  "GAS." + c.chainInfo.ChainID,
					SpendValue: fee.String(),
				},
			},
		},
	}, nil
}

func decodeReport(report []byte, metadata capabilities.RequestMetadata) (*platform.Report, error) {
	// Decode the report
	reportDecoded, err := platform.Decode(report)
	if err != nil {
		return nil, fmt.Errorf("failed to decode report [%s]: %w", string(report), err)
	}

	// Validate encoded report is prefixed with workflowID and executionID that match the request meta
	if reportDecoded.ExecutionID != metadata.WorkflowExecutionID {
		return nil, errors.New("decoded report execution ID does not match the request")
	} else if reportDecoded.WorkflowID != metadata.WorkflowID {
		return nil, errors.New("decoded report workflow ID does not match the request")
	}

	return reportDecoded, nil
}

func (c *writeTarget) RegisterToWorkflow(ctx context.Context, request capabilities.RegisterToWorkflowRequest) error {
	// TODO: notify the background WriteTxConfirmer (workflow registered)
	return nil
}

func (c *writeTarget) UnregisterFromWorkflow(ctx context.Context, request capabilities.UnregisterFromWorkflowRequest) error {
	// TODO: notify the background WriteTxConfirmer (workflow unregistered)
	return nil
}

// acceptAndConfirmWrite waits (until timeout) for the report to be accepted and (optionally) confirmed on-chain
// Emits Beholder messages:
//   - 'platform.write-target.WriteError'     if not accepted
//   - 'platform.write-target.WriteAccepted'  if accepted (with or without an error)
//   - 'platform.write-target.WriteError'     if accepted (with an error)
//   - 'platform.write-target.WriteConfirmed' if confirmed (until timeout)
func (c *writeTarget) acceptAndConfirmWrite(ctx context.Context, info requestInfo, txID uuid.UUID, query func(context.Context) (*TransmissionState, error)) error {
	attrs := c.traceAttributes(info.request.Metadata.WorkflowExecutionID)
	_, span := c.beholder.Tracer.Start(ctx, "Execute.acceptAndConfirmWrite", trace.WithAttributes(attrs...))
	defer span.End()

	lggr := logger.Named(c.lggr, "write-confirmer")

	// Timeout for the confirmation process
	timeout := c.config.ConfirmerTimeout.Duration()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Retry interval for the confirmation process
	interval := c.config.ConfirmerPollPeriod.Duration()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Helper to build monitoring (Beholder) messages
	// Notice: error skipped as implementation always returns nil
	capInfo, _ := c.Info(ctx)
	builder := NewMessageBuilder(c.chainInfo, capInfo)

	txFinalized, err := c.waitTxReachesTerminalStatus(ctx, lggr, txID)
	if err != nil {
		// We (eventually) failed to confirm the report was transmitted
		msg := builder.buildWriteError(&info, 0, "failed to wait until tx gets finalized", err.Error())
		lggr.Errorw("failed to wait until tx gets finalized", "txID", txID, "error", err)
		_ = c.beholder.ProtoEmitter.Emit(ctx, msg)
		return msg.AsError()
	}

	checkConfirmedStatus := query

	for {
		select {
		case <-ctx.Done():
			// We (eventually) failed to confirm the report was transmitted
			cause := "transaction was finalized, but report was not observed on chain before timeout"
			if !txFinalized {
				cause = "transaction failed and no other node managed to get report on chain before timeout"
			}
			msg := builder.buildWriteError(&info, 0, "write confirmation - failed", cause)
			_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, msg)
			return msg.AsError()
		case <-ticker.C:
			// Fetch the latest head from the chain (timestamp)
			head, err := c.cs.LatestHead(ctx)
			if err != nil {
				lggr.Errorw("failed to fetch the latest head", "txID", txID, "err", err)
				continue
			}

			// Check confirmation status (transmission state)
			state, err := checkConfirmedStatus(ctx)
			if err != nil {
				lggr.Errorw("failed to check confirmed status", "txID", txID, "err", err)
				continue
			}

			if state == nil {
				lggr.Infow("not confirmed yet - transmission state NOT visible", "txID", txID)
				continue
			}

			// We (eventually) confirmed the report was transmitted
			// Emit the confirmation message and return
			if !txFinalized {
				lggr.Infow("confirmed - transmission state visible but submitted by another node. This node's tx failed", "txID", txID)
			} else {
				lggr.Infow("confirmed - transmission state visible", "txID", txID)
			}

			// Source the transmitter address from the on-chain state
			info.reportTransmissionState = state

			_ = c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(&info, head))

			return nil
		}
	}
}

// Polls transaction status until it reaches one of terminal states [Finalized, Failed, Fatal]
func (c *writeTarget) waitTxReachesTerminalStatus(ctx context.Context, lggr logger.Logger, txID uuid.UUID) (finalized bool, err error) {
	// Retry interval for the confirmation process
	interval := c.config.ConfirmerPollPeriod.Duration()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-ticker.C:
			// Check TXM for status
			status, err := c.cw.GetTransactionStatus(ctx, txID.String())
			if err != nil {
				lggr.Errorw("failed to fetch the transaction status", "txID", txID, "err", err)
				continue
			}

			lggr.Debugw("txm - tx status", "txID", txID, "status", status)

			switch status {
			case commontypes.Finalized:
				// Notice: report write confirmation is only possible after a tx is accepted without an error
				// TODO: [Beholder] Emit 'platform.write-target.WriteAccepted' (useful to source tx hash, block number, and tx status/error)
				lggr.Infow("accepted", "txID", txID, "status", status)
				return true, nil
			case commontypes.Failed, commontypes.Fatal:
				// TODO: [Beholder] Emit 'platform.write-target.WriteError' if accepted with an error (surface specific on-chain error)
				lggr.Infow("transaction failed", "txID", txID, "status", status)
				return false, nil
			default:
				lggr.Infow("not accepted yet", "txID", txID, "status", status)
				continue
			}
		}
	}
}

// traceAttributes returns the attributes to be used for tracing
func (c *writeTarget) traceAttributes(workflowExecutionID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("capability_id", c.ID),
		attribute.String("capability_type", string(c.CapabilityType)),
		attribute.String("workflow_execution_id", workflowExecutionID),
	}
}

// asEmittedError returns the WriteError message as an (Go) error, after emitting it first
func (c *writeTarget) asEmittedError(ctx context.Context, e *wt.WriteError, attrKVs ...any) error {
	// Notice: we always want to log the error
	err := c.beholder.ProtoEmitter.EmitWithLog(ctx, e, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit error: %+w", err)
	}
	return e.AsError()
}
