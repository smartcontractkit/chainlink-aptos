package write_target

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/google/uuid"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-framework/capabilities/writetarget"

	aptosacc "github.com/smartcontractkit/chainlink-aptos/relayer/account"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/retry"
)

// aptos specific consts
type aptosTargetStrategy struct {
	cr commontypes.ContractReader
	cw commontypes.ContractWriter

	lggr      logger.Logger
	forwarder string
}

// chain-specific consts
// required field of target's config in the workflow spec
const (
	// Static contract info
	ContractName                            = "forwarder"
	ContractMethodName_report               = "report"
	ContractMethodName_getTransmissionState = "getTransmissionState"
	ContractMethodName_getTransmitter       = "getTransmitter"
)

var (
	_ writetarget.TargetStrategy = &aptosTargetStrategy{}
)

func NewAptosTargetStrategy(cr commontypes.ContractReader, cw commontypes.ContractWriter, lggr logger.Logger, forwarder string) *aptosTargetStrategy {
	return &aptosTargetStrategy{
		cr:        cr,
		cw:        cw,
		lggr:      lggr,
		forwarder: forwarder,
	}
}

func (t *aptosTargetStrategy) QueryTransmissionState(ctx context.Context, reportID uint16, request capabilities.CapabilityRequest) (*writetarget.TransmissionState, error) {
	receiver, err := getReceiver(request)
	if err != nil {
		return nil, err
	}

	rawExecutionID, err := hex.DecodeString(request.Metadata.WorkflowExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode workflowExecutionID: %w", err)
	}

	// Check whether the report was already transmitted on chain
	binding := commontypes.BoundContract{
		Address: t.forwarder,
		Name:    ContractName,
	}
	queryInputs := struct {
		Receiver            string
		WorkflowExecutionID []byte
		ReportID            uint16
	}{
		Receiver:            receiver,
		WorkflowExecutionID: rawExecutionID,
		ReportID:            reportID,
	}

	t.lggr.Debugw("querying [TransmissionState]", "binding", binding, "queryInputs", queryInputs)

	// Notice: if not confirmed the report is published yet, we're expected to submit the report on-chain (might be
	// competing with other nodes). We want to confirm this report was accepted and finalized eventually, or timeout
	// and emit an error - we store the confirm query

	// Helper to query the chain for the transmission state
	// TODO: it's unclear how to source the TransmissionState via an abstracted CR API call
	// Notice: this function is Aptos chain-specific (logic needs to be hidden behind the CR API call)
	query := func(ctx context.Context) (*writetarget.TransmissionState, error) {
		// Check if transmission state exists
		var transmitted bool
		readTransmissionState := binding.ReadIdentifier(ContractMethodName_getTransmissionState)
		err := t.cr.GetLatestValue(ctx, readTransmissionState, primitives.Unconfirmed, queryInputs, &transmitted)
		if err != nil {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmissionState]: %w", err)
		}

		t.lggr.Debugw("[forwarder.getTransmissionState] call output", "transmitted", transmitted)

		// nil state means the report was not transmitted yet
		if !transmitted {
			return nil, nil
		}

		// Fetch the transmitter address from the chain (decode output type)
		var transmitterAddr struct {
			Vec []string
		}
		readTransmitter := binding.ReadIdentifier(ContractMethodName_getTransmitter)
		err = t.cr.GetLatestValue(ctx, readTransmitter, primitives.Unconfirmed, queryInputs, &transmitterAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: %w", err)
		}

		t.lggr.Debugw("[forwarder.getTransmitter] call output", "transmitterAddr", transmitterAddr)

		if len(transmitterAddr.Vec) == 0 {
			return nil, fmt.Errorf("failed to call [forwarder.getTransmitter]: unexpected empty result")
		}

		address, err := aptosacc.HexAddrToAccountAddress(transmitterAddr.Vec[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse transmitter address: %w", err)
		}

		return &writetarget.TransmissionState{Transmitter: address.String(), Status: writetarget.TransmissionStateSucceeded}, nil
	}

	// Fetch the transmission state, retry with a default backoff strategy
	state, err := retry.WithRetry(ctx, t.lggr, query)

	return state, err
}

func (t *aptosTargetStrategy) TransmitReport(ctx context.Context, report []byte, reportContext []byte, signatures [][]byte, request capabilities.CapabilityRequest) (string, error) {
	txID, err := uuid.NewUUID() // NOTE: CW expects us to generate an ID, rather than return one
	if err != nil {
		// This should never happen
		return "", err
	}

	receiver, err := getReceiver(request)
	if err != nil {
		return txID.String(), err
	}

	// Note: The codec that ContractWriter uses to encode the parameters for the contract ABI cannot handle
	// `nil` values, including for slices. Until the bug is fixed we need to ensure that there are no
	// `nil` values passed in the request.
	req := struct {
		Receiver   string
		RawReport  []byte
		Signatures [][]byte
	}{
		Receiver:   receiver,
		RawReport:  append(reportContext, report...),
		Signatures: signatures,
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
	err = t.cw.SubmitTransaction(ctx, ContractName, ContractMethodName_report, req, txID.String(), t.forwarder, &meta, value)
	return txID.String(), err
}
