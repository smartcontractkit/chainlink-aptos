// NOTE: file is based on the generic write target capability, but we're slightly modifying it until the two implementations can be merged
// in particular, we need to invert the calling flow for Aptos so receiver is the entrypoint
package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
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

	transmitterAddress string
	forwarderAddress   string
}

type WriteTargetOpts struct {
	ID string

	Logger logger.Logger

	ChainService     commontypes.ChainService
	ContractReader   commontypes.ContractReader
	ChainWriter      commontypes.ChainWriter
	ConfigValidateFn func(config Config) error

	TransmitterAddress string
	ForwarderAddress   string
}

// Capability-specific configuration
type Config struct {
	Address string
}

func NewWriteTarget(opts WriteTargetOpts) capabilities.TargetCapability {
	capInfo := capabilities.MustNewCapabilityInfo(opts.ID, capabilities.CapabilityTypeTarget, capabilityName)
	selfLogger := logger.Named(opts.Logger, capabilityName)

	// Initialize the Beholder client with a local logger a custom Emitter
	protoEmitter := monitor.NewProtoEmitter(selfLogger, beholder.GetClient())
	beholder := &monitor.BeholderClient{beholder.GetClient(), protoEmitter}

	return &writeTarget{
		capInfo,
		selfLogger,
		beholder,
		opts.ChainService,
		opts.ContractReader,
		opts.ChainWriter,
		opts.ConfigValidateFn,
		opts.TransmitterAddress,
		opts.ForwarderAddress,
	}
}

func success() capabilities.CapabilityResponse {
	return capabilities.CapabilityResponse{}
}

type reportInfo struct {
	reportID      uint16
	reportContext []byte
	report        []byte
	signersNum    uint32
}

type requestInfo struct {
	forwarder   string
	receiver    string
	transmitter string

	reportInfo *reportInfo
}

func (c *writeTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	c.lggr.Debugw("Execute", "request", request)

	// Helper to keep track of the info
	info := &requestInfo{
		forwarder:   c.forwarderAddress,
		receiver:    "N/A",
		transmitter: c.transmitterAddress,
		reportInfo: &reportInfo{
			reportID:      0, // N/A
			reportContext: nil,
			report:        nil,
			signersNum:    0, // N/A
		},
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
	reportDecoded, err := Decode(inputs.Report)
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
	readID := binding.ReadIdentifier(contractMethodName_getTransmissionState)
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

	c.lggr.Debugw("WriteTarget non-empty report",
		"reportID", info.reportInfo.reportID,
		"report", "0x"+hex.EncodeToString(inputs.Report),
		"reportLen", len(inputs.Report),
		"reportDecoded", reportDecoded,
		"reportContext", "0x"+hex.EncodeToString(inputs.Context),
		"reportContextLen", len(inputs.Context),
		"signaturesLen", len(inputs.Signatures),
		"executionID", request.Metadata.WorkflowExecutionID,
	)

	c.lggr.Debugw("WriteTarget - calling [forwarder.getTransmissionState]", "binding", binding, "queryInputs", queryInputs)

	// Notice: if not confirmed the report is published yet, we're expected to submit the report on-chain (might be
	// competing with other nodes). We want to confirm this report was accepted and finalized eventually, or timeout
	// and emit an error - we store the confirm query

	// Helper to query the chain for the transmission state
	query := func(ctx context.Context) (bool, error) {
		var transmitted bool
		err := c.cr.GetLatestValue(ctx, readID, primitives.Unconfirmed, queryInputs, &transmitted)
		return transmitted, err
	}

	transmitted, err := query(ctx)
	if err != nil {
		msg := builder.buildWriteError(info, 0, "failed to call [forwarder.getTransmissionState]", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	} else if transmitted == true {
		finalized := false
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(info, head, finalized))
		return success(), nil
	}

	c.lggr.Infow("WriteTarget on-chain report check done - attempting to push to txmgr",
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

	// TODO: [Beholder] Emit 'write-target.WriteAccepted' by pooling for TXM status finalized/failed

	// TODO: implement a background WriteTxConfirmer to periodically source new events/transactions,
	// relevant to this forwarder), and emit write-tx-accepted/confirmed events.

	go c.confirmWrite(ctx, *info, txID, query)
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

// TODO: replace with a proper implementation
// A dummy confirmer that sleeps some time before confirming the write
// confirmWrite waits for the report to be transmitted on-chain and emits the appropriate Beholder messages
func (c *writeTarget) confirmWrite(ctx context.Context, info requestInfo, txID uuid.UUID, query func(context.Context) (bool, error)) {
	// Sleep for N sec + a random amount of time
	rand.Seed(time.Now().UnixNano())
	n := 4
	r := rand.Intn(200)
	time.Sleep(time.Duration(n)*time.Second + time.Duration(r)*time.Millisecond)

	// Helper to build monitoring (Beholder) messages
	builder := &messageBuilder{}

	// Fetch the latest head from the chain (timestamp)
	head, err := c.cs.LatestHead(ctx)
	if err != nil {
		msg := "failed to fetch the latest head:" + err.Error()
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteError(&info, 0, "failed to confirm the report was transmitted", msg))
	}

	// Check the transmission state
	ctx = context.Background()
	transmitted, err := query(ctx)
	if err != nil || transmitted != true {
		var msg string
		if err != nil {
			msg = "failed to call [forwarder.getTransmissionState]:" + err.Error()
		} else {
			msg = "unable to observe the report was transmitted"
		}
		// We (eventually) failed to confirm the report was transmitted
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteError(&info, 0, "failed to confirm the report was transmitted", msg))
	} else {
		// We (eventually) confirmed the report was transmitted
		finalized := false
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteConfirmed(&info, head, finalized))
	}
}
