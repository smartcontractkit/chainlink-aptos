// NOTE: file is based on the generic write target capability, but we're slightly modifying it until the two implementations can be merged
// in particular, we need to invert the calling flow for Aptos so receiver is the entrypoint
package write_target

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"google.golang.org/protobuf/proto"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/values"

	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

var (
	_ capabilities.ActionCapability = &WriteTarget{}
)

// required field of target's config in the workflow spec
const signedReportField = "signed_report"

type WriteTarget struct {
	capabilities.CapabilityInfo
	cr               commontypes.ContractReader
	cw               commontypes.ChainWriter
	forwarderAddress string
	lggr             logger.Logger
}

func NewWriteTarget(lggr logger.Logger, id string, cr commontypes.ContractReader, cw commontypes.ChainWriter, forwarderAddress string) *WriteTarget {
	return &WriteTarget{
		capabilities.MustNewCapabilityInfo(id, capabilities.CapabilityTypeTarget, "WriteTarget"),
		cr,
		cw,
		forwarderAddress,
		logger.Named(lggr, "WriteTarget"),
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

func (c *WriteTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (capabilities.CapabilityResponse, error) {
	// TODO: wrap body in a fn, handle errors by publishing [Beholder] Emit 'write-target.WriteError'
	c.lggr.Debugw("Execute", "request", request)

	reqConfig, err := parseConfig(request.Config)
	if err != nil {
		return capabilities.CapabilityResponse{}, err
	}

	signedReport, ok := request.Inputs.Underlying[signedReportField]
	if !ok {
		return capabilities.CapabilityResponse{}, fmt.Errorf("missing required field %s", signedReportField)
	}

	inputs := types.SignedReport{}
	if err = signedReport.UnwrapTo(&inputs); err != nil {
		return capabilities.CapabilityResponse{}, err
	}

	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		return capabilities.CapabilityResponse{}, err
	}
	reportID, _ := binary.Uvarint(inputs.ID)

	// [Beholder] Emit 'write-target.WriteInitiated'
	msgWriteInitiated := &wt.WriteInitiated{
		Forwarder: c.forwarderAddress,
		Receiver:  reqConfig.Address,
		// TODO: figure out how to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
		Transmitter: "N/A",
		ReportId:    uint32(reportID),
	}
	_, err = proto.Marshal(msgWriteInitiated)
	if err != nil {
		return capabilities.CapabilityResponse{}, err
	}
	c.lggr.Infow("[Beholder.emit] 'write-target.WriteInitiated'", "message", msgWriteInitiated.String())

	emitWriteSkipped := func() error {
		// [Beholder] Emit 'write-target.WriteSkipped'
		msgWriteSkipped := &wt.WriteSkipped{
			Forwarder: c.forwarderAddress,
			Receiver:  reqConfig.Address,
			// TODO: figure out how to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
			Transmitter: "N/A",
			ReportId:    uint32(reportID),
		}
		_, err = proto.Marshal(msgWriteInitiated)
		if err != nil {
			return err
		}
		c.lggr.Infow("[Beholder.emit] 'write-target.WriteSkipped'", "message", msgWriteSkipped.String())
		return nil
	}

	// Check whether the report is valid (e.g., not empty)
	if len(inputs.Report) == 0 {
		// We received any empty report -- this means we should skip transmission.
		emitWriteSkipped()
		c.lggr.Debugw("Skipping empty report", "request", request)
		return success(), nil
	}
	// TODO: validate encoded report is prefixed with workflowID and executionID that match the request meta

	// Check whether value was already transmitted on chain
	queryInputs := struct {
		Receiver            string
		WorkflowExecutionID []byte
		ReportID            uint16
	}{
		Receiver:            reqConfig.Address,
		WorkflowExecutionID: rawExecutionID,
		ReportID:            uint16(reportID),
	}

	var transmitted bool
	if err = c.cr.GetLatestValue(ctx, "forwarder", "getTransmissionState", primitives.Unconfirmed, queryInputs, &transmitted); err != nil {
		return capabilities.CapabilityResponse{}, err
	}
	if transmitted == true {
		emitWriteSkipped()
		c.lggr.Infow("WriteTarget report already onchain - returning without a tranmission attempt", "executionID", request.Metadata.WorkflowExecutionID)
		return success(), nil
	}

	c.lggr.Infow("WriteTarget non-empty report - attempting to push to txmgr", "request", request, "reportLen", len(inputs.Report), "reportContextLen", len(inputs.Context), "nSignatures", len(inputs.Signatures), "executionID", request.Metadata.WorkflowExecutionID)
	txID, err := uuid.NewUUID() // NOTE: CW expects us to generate an ID, rather than return one
	if err != nil {
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
		Receiver:   reqConfig.Address,
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

	meta := commontypes.TxMeta{WorkflowExecutionID: &request.Metadata.WorkflowExecutionID}
	value := big.NewInt(0)
	if err := c.cw.SubmitTransaction(ctx, "forwarder", "report", req, txID.String(), c.forwarderAddress, &meta, value); err != nil {
		return capabilities.CapabilityResponse{}, err
	}

	// [Beholder] Emit 'write-target.WriteSent'
	msgWriteSent := &wt.WriteSent{
		Forwarder: c.forwarderAddress,
		Receiver:  reqConfig.Address,
		// TODO: figure out how to source the transmitter (e.g., c.cw.config.Functions["forwarder"].FromAddress)
		Transmitter: "N/A",
		ReportId:    uint32(reportID),

		// TODO: figure out how to source the tx hash
		TxHash:        "N/A",
		XMetadata:     []byte{},
		XMetadataType: "aptos-tx-sent-metadata",
	}
	_, err = proto.Marshal(msgWriteSent)
	if err != nil {
		return nil, err
	}
	c.lggr.Infow("[Beholder.emit] 'write-target.WriteSent'", "message", msgWriteSent.String())
	c.lggr.Debugw("Transaction submitted", "request", request, "transaction", txID)

	// TODO: source tx receipt (wait for a tx to be included in a block)
	// TODO: [Beholder] Emit 'write-target.WriteAccepted'

	return success(), nil
}

func (c *WriteTarget) RegisterToWorkflow(ctx context.Context, request capabilities.RegisterToWorkflowRequest) error {
	// TODO: start a process responsible for monitoring the chain and publishing [Beholder] Emit 'write-target.WriteConfirmed'
	// TODO: start a process responsible for monitoring the WT account balance
	return nil
}

func (c *WriteTarget) UnregisterFromWorkflow(ctx context.Context, request capabilities.UnregisterFromWorkflowRequest) error {
	// TODO: stop a process responsible for monitoring the chain and publishing [Beholder] Emit 'write-target.WriteConfirmed'
	// TODO: stop a process responsible for monitoring the WT account balance
	return nil
}
