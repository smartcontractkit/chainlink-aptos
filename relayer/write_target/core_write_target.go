// NOTE: file is based on the generic write target capability, but we're slightly modifying it until the two implementations can be merged
// in particular, we need to invert the calling flow for Aptos so receiver is the entrypoint
package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/values"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chainwriter"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
	aptosutils "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/utils"
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

	cr       commontypes.ContractReader
	cw       commontypes.ChainWriter
	cwConfig chainwriter.ChainWriterConfig

	forwarderAddress string
}

type WriteTargetOpts struct {
	ID string

	Logger   logger.Logger
	Beholder *beholder.Client

	ContractReader    commontypes.ContractReader
	ChainWriter       commontypes.ChainWriter
	ChainWriterConfig chainwriter.ChainWriterConfig

	ForwarderAddress string
}

func NewWriteTarget(opts WriteTargetOpts) capabilities.TargetCapability {
	capInfo := capabilities.MustNewCapabilityInfo(opts.ID, capabilities.CapabilityTypeTarget, capabilityName)
	selfLogger := logger.Named(opts.Logger, capabilityName)

	// Initialize the Beholder client with a local logger a custom Emitter
	protoEmitter := monitor.NewProtoEmitter(selfLogger, opts.Beholder)
	beholderClient := &monitor.BeholderClient{opts.Beholder, protoEmitter}

	return &writeTarget{
		capInfo,
		selfLogger,
		beholderClient,
		opts.ContractReader,
		opts.ChainWriter,
		opts.ChainWriterConfig,
		opts.ForwarderAddress,
	}
}

type AptosConfig struct {
	Address string
}

func parseConfig(rawConfig *values.Map) (config AptosConfig, err error) {
	if err := rawConfig.UnwrapTo(&config); err != nil {
		return config, err
	}
	address := aptos.AccountAddress{}
	if err = address.ParseStringRelaxed(config.Address); err != nil {
		return config, fmt.Errorf("'%v' is not a valid address", config.Address)
	}
	return config, nil
}

func success() capabilities.CapabilityResponse {
	return capabilities.CapabilityResponse{}
}

type requestContext struct {
	forwarder   string
	receiver    string
	transmitter string
	reportID    uint64
}

func (c *writeTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	c.lggr.Debugw("Execute", "request", request)

	// Helper to keep track of the context
	context := requestContext{
		forwarder:   c.forwarderAddress,
		receiver:    "N/A",
		transmitter: "N/A",
		reportID:    0, // N/A
	}
	// Helper to build monitoring (Beholder) messages
	builder := &messageBuilder{}

	// Try to source the transmitter
	transmitter, err := c.getTransmitter()
	if err != nil {
		msg := builder.buildWriteError(context, 0, "failed to source the transmitter", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}
	context.transmitter = transmitter

	// Try to parse the request (WT-specific) config
	reqConfig, err := parseConfig(request.Config)
	if err != nil {
		msg := builder.buildWriteError(context, 0, "failed to parse config", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Source the receiver address from the config
	context.receiver = reqConfig.Address

	// Try to source the signed report from the request
	signedReport, ok := request.Inputs.Underlying[keySignedReport]
	if !ok {
		cause := fmt.Sprintf("input missing required field: '%s'", keySignedReport)
		msg := builder.buildWriteError(context, 0, "failed to source the signed report", cause)
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Try to decode the signed report
	inputs := types.SignedReport{}
	if err = signedReport.UnwrapTo(&inputs); err != nil {
		msg := builder.buildWriteError(context, 0, "failed to parse signed report", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	// Source the report ID from the input
	context.reportID, _ = binary.Uvarint(inputs.ID)

	// Try to decode the workflow execution ID
	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		msg := builder.buildWriteError(context, 0, "failed to decode the workflow execution ID", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteInitiated(context))

	// Check whether the report is valid (e.g., not empty)
	if len(inputs.Report) == 0 {
		// We received any empty report -- this means we should skip transmission.
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSkipped(context, "empty report"))
		return success(), nil
	}
	// TODO: validate encoded report is prefixed with workflowID and executionID that match the request meta

	// Try to check whether the report was already transmitted on chain
	queryInputs := struct {
		Receiver            string
		WorkflowExecutionID []byte
		ReportID            uint16
	}{
		Receiver:            context.receiver,
		WorkflowExecutionID: rawExecutionID,
		ReportID:            uint16(context.reportID),
	}

	var transmitted bool
	if err = c.cr.GetLatestValue(ctx, contractName, contractMethodName_getTransmissionState, primitives.Unconfirmed, queryInputs, &transmitted); err != nil {
		msg := builder.buildWriteError(context, 0, "failed to call [forwarder.getTransmissionState]", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	} else if transmitted == true {
		c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSkipped(context, "report already on-chain"))
		return success(), nil
	}

	c.lggr.Infow("WriteTarget non-empty report - attempting to push to txmgr",
		"request", request,
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
		Receiver:   context.receiver,
		RawReport:  append(inputs.Context, inputs.Report...),
		Signatures: inputs.Signatures,
	}

	if req.RawReport == nil {
		req.RawReport = make([]byte, 0)
	}

	if req.Signatures == nil {
		req.Signatures = make([][]byte, 0)
	}
	c.lggr.Debugw("Transaction raw report", "report", hex.EncodeToString(req.RawReport))

	// Try to submit the transaction
	meta := commontypes.TxMeta{WorkflowExecutionID: &request.Metadata.WorkflowExecutionID}
	value := big.NewInt(0)
	err = c.cw.SubmitTransaction(ctx, contractName, contractMethodName_report, req, txID.String(), context.forwarder, &meta, value)
	if err != nil {
		msg := builder.buildWriteError(context, 0, "failed to invoke [forwarder.report]", err.Error())
		return capabilities.CapabilityResponse{}, msg.AsEmittedError(ctx, c.beholder)
	}

	c.lggr.Debugw("Transaction submitted", "request", request, "transaction-id", txID)
	c.beholder.ProtoEmitter.EmitWithLog(ctx, builder.buildWriteSent(context, txID.String()))

	// TODO: source the TxHash from CW -> TXM by generated TxID)
	// TODO: have background WriteConfirmer source relevant txs and their receipts (wait for a tx to be included in a block)
	// TODO: [Beholder] Emit 'write-target.WriteAccepted'
	// TODO: [Beholder] Emit 'write-target.WriteConfirmed'
	return success(), nil
}

func (c *writeTarget) RegisterToWorkflow(ctx context.Context, request capabilities.RegisterToWorkflowRequest) error {
	// TODO: store locally, and if trigger seen

	// TODO: start a process responsible for monitoring the chain and publishing [Beholder] Emit 'write-target.WriteConfirmed'
	return nil
}

func (c *writeTarget) UnregisterFromWorkflow(ctx context.Context, request capabilities.UnregisterFromWorkflowRequest) error {
	// TODO: stop a process responsible for monitoring the chain and publishing [Beholder] Emit 'write-target.WriteConfirmed'
	return nil
}

// getTransmitter sources the transmitter address from the CW config
func (c *writeTarget) getTransmitter() (string, error) {
	// Try to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
	moduleConfig, ok := c.cwConfig.Modules[contractName]
	if !ok {
		return "", fmt.Errorf("no such contract: %s", contractName)
	}

	functionConfig, ok := moduleConfig.Functions[contractMethodName_report]
	if !ok {
		return "", fmt.Errorf("no such method: %s", contractMethodName_report)
	}

	// Notice: reusing logic from the TXM which sources the transmitter this way
	transmitter := functionConfig.FromAddress
	if transmitter == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		ed25519PublicKey, err := aptosutils.HexToEd25519PublicKey(functionConfig.PublicKey)
		if err != nil {
			return "", fmt.Errorf("failed to convert public key: %+w", err)
		}
		acc := aptosutils.Ed25519PublicKeyToAccount(ed25519PublicKey)
		transmitter = acc.String()
	}
	return transmitter, nil
}
