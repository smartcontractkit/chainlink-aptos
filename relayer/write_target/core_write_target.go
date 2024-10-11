// NOTE: file is based on the generic write target capability, but we're slightly modifying it until the two implementations can be merged
// in particular, we need to invert the calling flow for Aptos so receiver is the entrypoint
package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/keystone"
)

var (
	_ capabilities.TargetCapability = &writeTarget{}
)

// required field of target's config in the workflow spec
const (
	capabilityName = "write-target"

	// Input keys
	keySignedReport = "signed_report"

	// Static contract info
	contractName                            = "forwarder"
	contractMethodName_report               = "report"
	contractMethodName_getTransmissionState = "getTransmissionState"
	contractMethodName_getTransmitter       = "getTransmitter"
)

type writeTarget struct {
	capabilities.CapabilityInfo

	lggr logger.Logger
	// Local beholder client, also hosting the protobuf emitter
	beholder *monitor.BeholderClient

	cs               commontypes.ChainService
	cr               commontypes.ContractReader
	cw               commontypes.ChainWriter
	configValidateFn func(config Config) error

	nodeAddress      string
	forwarderAddress string
}

type WriteTargetOpts struct {
	ID string

	Logger   logger.Logger
	Beholder *monitor.BeholderClient

	ChainService     commontypes.ChainService
	ContractReader   commontypes.ContractReader
	ChainWriter      commontypes.ChainWriter
	ConfigValidateFn func(config Config) error

	NodeAddress      string
	ForwarderAddress string
}

// Capability-specific configuration
type Config struct {
	Address string
}

type TransmissionState struct {
	Transmitter string
	Success     bool
}

func NewWriteTarget(opts WriteTargetOpts) capabilities.TargetCapability {
	capInfo := capabilities.MustNewCapabilityInfo(opts.ID, capabilities.CapabilityTypeTarget, capabilityName)
	selfLogger := logger.Named(opts.Logger, capabilityName)

	return &writeTarget{
		capInfo,
		selfLogger,
		opts.Beholder,
		opts.ChainService,
		opts.ContractReader,
		opts.ChainWriter,
		opts.ConfigValidateFn,
		opts.NodeAddress,
		opts.ForwarderAddress,
	}
}

func success() capabilities.CapabilityResponse {
	return capabilities.CapabilityResponse{}
}

type reportInfo struct {
	reportContext []byte
	report        []byte
	signersNum    uint32

	// Decoded report fields
	reportID            uint16
	workflowExecutionID string
}

type requestInfo struct {
	node      string
	forwarder string
	receiver  string

	reportInfo              *reportInfo
	reportTransmissionState *TransmissionState
}

func (c *writeTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	attrs := c.traceAttributes(request.Metadata.WorkflowExecutionID)
	_, span := c.beholder.Tracer.Start(ctx, "Execute", trace.WithAttributes(attrs...))
	defer span.End()

	c.lggr.Debugw("Execute", "request", request)

	// Helper to keep track of the info
	info := &requestInfo{
		node:      c.nodeAddress,
		forwarder: c.forwarderAddress,
		receiver:  "N/A",
		reportInfo: &reportInfo{
			reportContext:       nil,
			report:              nil,
			signersNum:          0, // N/A
			reportID:            0, // N/A
			workflowExecutionID: request.Metadata.WorkflowExecutionID,
		},
		reportTransmissionState: nil,
	}
	// Helper to build monitoring (Beholder) messages
	builder := &messageBuilder{}

	// Parse the request (WT-specific) config
	var reqConfig Config
	err := request.Config.UnwrapTo(&reqConfig)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to parse config", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Validate the config
	err = c.configValidateFn(reqConfig)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to validate config", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Source the receiver address from the config
	info.receiver = reqConfig.Address

	// Source the signed report from the request
	signedReport, ok := request.Inputs.Underlying[keySignedReport]
	if !ok {
		cause := fmt.Sprintf("input missing required field: '%s'", keySignedReport)
		msg := builder.buildWriteError(info, 0, "failed to source the signed report", cause)
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Decode the signed report
	inputs := types.SignedReport{}
	if err = signedReport.UnwrapTo(&inputs); err != nil {
		msg := builder.buildWriteError(info, 0, "failed to parse signed report", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Source the report ID from the input
	info.reportInfo.reportID = binary.BigEndian.Uint16(inputs.ID)

	// Decode the workflow execution ID
	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to decode the workflow execution ID", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteInitiated(info))

	// Check whether the report is valid (e.g., not empty)
	if len(inputs.Report) == 0 {
		// We received any empty report -- this means we should skip transmission.
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSkipped(info, "empty report"))
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
	reportDecoded, err := keystone.Decode(inputs.Report)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to decode the report", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Validate encoded report is prefixed with workflowID and executionID that match the request meta
	if reportDecoded.ExecutionID != request.Metadata.WorkflowExecutionID {
		msg := builder.buildWriteError(info, 0, "decoded report execution ID does not match the request", "")
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	} else if reportDecoded.WorkflowID != request.Metadata.WorkflowID {
		msg := builder.buildWriteError(info, 0, "decoded report workflow ID does not match the request", "")
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Check whether the report was already transmitted on chain
	binding := commontypes.BoundContract{
		Address: info.forwarder,
		Name:    contractName,
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

	// Fetch the latest head from the chain (timestamp)
	head, err := c.cs.LatestHead(ctx)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to fetch the latest head", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
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
		readTransmissionState := binding.ReadIdentifier(contractMethodName_getTransmissionState)
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
		var transmitter struct {
			Vec []string
		}
		readTransmitter := binding.ReadIdentifier(contractMethodName_getTransmitter)
		err = c.cr.GetLatestValue(ctx, readTransmitter, primitives.Unconfirmed, queryInputs, &transmitter)
		if err != nil {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: %w", err)
		}

		c.lggr.Debugw("[forwarder.getTransmitter] call output", "transmitter", transmitter)

		if len(transmitter.Vec) == 0 {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: unexpected empty result")
		}

		return &TransmissionState{Transmitter: transmitter.Vec[0], Success: true}, nil
	}

	state, err := query(ctx)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to fetch [TransmissionState]", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	if state != nil {
		// Source the transmitter address from the on-chain state
		info.reportTransmissionState = state

		finalized := false
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(info, head, finalized))
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
	err = c.cw.SubmitTransaction(ctx, contractName, contractMethodName_report, req, txID.String(), info.forwarder, &meta, value)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to invoke [forwarder.report]", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	c.lggr.Debugw("Transaction submitted", "request", request, "transaction-id", txID)
	c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSent(info, head, txID.String()))

	// TODO: implement a background WriteTxConfirmer to periodically source new events/transactions,
	// relevant to this forwarder), and emit write-tx-accepted/confirmed events.

	go c.acceptAndConfirmWrite(ctx, *info, txID, query)
	return success(), nil
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
//   - 'write-target.WriteError'     if not accepted
//   - 'write-target.WriteAccepted'  if accepted (with or without an error)
//   - 'write-target.WriteError'     if accepted (with an error)
//   - 'write-target.WriteConfirmed' if confirmed (until timeout)
func (c *writeTarget) acceptAndConfirmWrite(ctx context.Context, info requestInfo, txID uuid.UUID, query func(context.Context) (*TransmissionState, error)) {
	attrs := c.traceAttributes(info.reportInfo.workflowExecutionID)
	_, span := c.beholder.Tracer.Start(ctx, "Execute.acceptAndConfirmWrite", trace.WithAttributes(attrs...))
	defer span.End()

	// TODO: needs to be configurable
	timeout := 10 * time.Second // Timeout for the confirmation process
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// TODO: needs to be configurable
	ticker := time.NewTicker(1 * time.Second) // Retry interval
	defer ticker.Stop()

	// Helper to build monitoring (Beholder) messages
	builder := &messageBuilder{}

	// Fn helpers
	checkAcceptedStatus := func(ctx context.Context) (bool, error) {
		// TODO: check TXM for status
		return true, nil
	}
	checkConfirmedStatus := query

	// Store the acceptance status
	accepted := false

	for {
		select {
		case <-ctx.Done():
			// We (eventually) failed to confirm the report was transmitted
			c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteError(&info, 0, "write confirmation - failed", "timed out"))
			return
		case <-ticker.C:
			// Fetch the latest head from the chain (timestamp)
			head, err := c.cs.LatestHead(ctx)
			if err != nil {
				c.lggr.Errorw("write confirmation - failed to fetch the latest head", "txID", txID, "err", err)
				continue
			}

			if !accepted {
				// Check acceptance status
				accepted, err := checkAcceptedStatus(ctx)
				if err != nil {
					c.lggr.Errorw("write confirmation - failed to check accepted status", "txID", txID, "err", err)
					continue
				}

				if accepted {
					c.lggr.Infow("write confirmation - accepted", "txID", txID)
					// TODO: [Beholder] Emit 'write-target.WriteAccepted' by pooling for TXM status finalized/failed

					// TODO: check if accepted with an error (e.g., on-chain revert)
					acceptedWithErr := false
					if acceptedWithErr {
						// TODO: [Beholder] Emit 'write-target.WriteError' if accepted with an error

						// Notice: no return, we continue to check for confirmation (should be accepted by another node)
					}
				} else {
					c.lggr.Infow("write confirmation - not accepted yet", "txID", txID)
					continue
				}
			}

			// Check confirmation status (transmission state)
			state, err := checkConfirmedStatus(ctx)
			if err != nil {
				c.lggr.Errorw("write confirmation - failed to check confirmed status", "txID", txID, "err", err)
				continue
			}

			// If confirmed, emit the confirmation message and return
			if state != nil {
				// We (eventually) confirmed the report was transmitted
				c.lggr.Infow("write confirmation - confirmed", "txID", txID)

				// Source the transmitter address from the on-chain state
				info.reportTransmissionState = state

				finalized := false
				c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(&info, head, finalized))
				return
			}
			c.lggr.Infow("write confirmation - not confirmed yet", "txID", txID)
		}
	}
}

// traceAttributes returns the attributes to be used for tracing
func (c *writeTarget) traceAttributes(workflowExecutionID string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("capability.id", c.ID),
		attribute.String("capability.version", c.Version()),
		attribute.String("capability.type", string(c.CapabilityType)),
		attribute.String("capability.instance", c.lggr.Name()), // full name from logger
		attribute.String("capability.executionID", workflowExecutionID),
	}
}
