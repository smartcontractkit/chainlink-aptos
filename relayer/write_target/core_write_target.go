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

	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities/consensus/ocr3/types"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/values"
)

var (
	_ capabilities.ActionCapability = &WriteTarget{}
)

// required field of target's config in the workflow spec
const signedReportField = "signed_report"

type WriteTarget struct {
	cr               commontypes.ContractReader
	cw               commontypes.ChainWriter
	forwarderAddress string
	capabilities.CapabilityInfo
	lggr logger.Logger
}

func NewWriteTarget(lggr logger.Logger, id string, cr commontypes.ContractReader, cw commontypes.ChainWriter, forwarderAddress string) *WriteTarget {
	info := capabilities.MustNewCapabilityInfo(
		id,
		capabilities.CapabilityTypeTarget,
		"Write target.",
	)

	logger := logger.Named(lggr, "WriteTarget")

	return &WriteTarget{
		cr,
		cw,
		forwarderAddress,
		info,
		logger,
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

func success() <-chan capabilities.CapabilityResponse {
	callback := make(chan capabilities.CapabilityResponse)
	go func() {
		callback <- capabilities.CapabilityResponse{}
		close(callback)
	}()
	return callback
}

func (cap *WriteTarget) Execute(ctx context.Context, request capabilities.CapabilityRequest) (<-chan capabilities.CapabilityResponse, error) {
	cap.lggr.Debugw("Execute", "request", request)

	reqConfig, err := parseConfig(request.Config)
	if err != nil {
		return nil, err
	}

	signedReport, ok := request.Inputs.Underlying[signedReportField]
	if !ok {
		return nil, fmt.Errorf("missing required field %s", signedReportField)
	}

	inputs := types.SignedReport{}
	if err = signedReport.UnwrapTo(&inputs); err != nil {
		return nil, err
	}

	if len(inputs.Report) == 0 {
		// We received any empty report -- this means we should skip transmission.
		cap.lggr.Debugw("Skipping empty report", "request", request)
		return success(), nil
	}
	// TODO: validate encoded report is prefixed with workflowID and executionID that match the request meta

	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		return nil, err
	}
	// Check whether value was already transmitted on chain
	reportID, _ := binary.Uvarint(inputs.ID)
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
	if err = cap.cr.GetLatestValue(ctx, "forwarder", "getTransmissionState", primitives.Unconfirmed, queryInputs, &transmitted); err != nil {
		return nil, err
	}
	if transmitted == true {
		cap.lggr.Infow("WriteTarget report already onchain - returning without a tranmission attempt", "executionID", request.Metadata.WorkflowExecutionID)
		return success(), nil
	}

	cap.lggr.Infow("WriteTarget non-empty report - attempting to push to txmgr", "request", request, "reportLen", len(inputs.Report), "reportContextLen", len(inputs.Context), "nSignatures", len(inputs.Signatures), "executionID", request.Metadata.WorkflowExecutionID)
	txID, err := uuid.NewUUID() // NOTE: CW expects us to generate an ID, rather than return one
	if err != nil {
		return nil, err
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
	cap.lggr.Debugw("Transaction raw report", "report", hex.EncodeToString(req.RawReport))

	meta := commontypes.TxMeta{WorkflowExecutionID: &request.Metadata.WorkflowExecutionID}
	value := big.NewInt(0)
	if err := cap.cw.SubmitTransaction(ctx, "forwarder", "report", req, txID.String(), cap.forwarderAddress, &meta, value); err != nil {
		return nil, err
	}
	cap.lggr.Debugw("Transaction submitted", "request", request, "transaction", txID)
	return success(), nil
}

func (cap *WriteTarget) RegisterToWorkflow(ctx context.Context, request capabilities.RegisterToWorkflowRequest) error {
	return nil
}

func (cap *WriteTarget) UnregisterFromWorkflow(ctx context.Context, request capabilities.UnregisterFromWorkflowRequest) error {
	return nil
}
