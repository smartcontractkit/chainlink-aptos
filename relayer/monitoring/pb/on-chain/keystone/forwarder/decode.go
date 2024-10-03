package forwarder

import (
	"encoding/hex"
	"fmt"

	wt_msg "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/write_target"
)

// DecodeAsReportProcessed decodes a 'write-target.WriteConfirmed' message
// as a 'keytone.forwarder.ReportProcessed' message
func DecodeAsReportProcessed(m *wt_msg.WriteConfirmed) (*ReportProcessed, error) {
	// Decode the confirmed report (WT -> Keystone forwarder)
	r, err := wt.Decode(m.Report)
	if err != nil {
		return nil, fmt.Errorf("failed to decode report: %w", err)
	}

	executionID, err := hex.DecodeString(r.ExecutionID)
	if err != nil {
		return nil, fmt.Errorf("failed to decode execution ID: %w", err)
	}

	return &ReportProcessed{
		// Event data
		Receiver:            m.Receiver,
		WorkflowExecutionId: executionID,
		ReportId:            m.ReportId,
		Success:             m.Success,

		// Notice: we skip head/tx data here (unknown), as we map from 'write-target.WriteConfirmed'
		// and not from tx/event data (e.g., 'write-target.WriteTxConfirmed')
	}, nil
}
