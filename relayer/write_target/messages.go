package write_target

import (
	"encoding/hex"

	"github.com/smartcontractkit/chainlink-common/pkg/types"

	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

type messageBuilder struct{}

func (m *messageBuilder) buildWriteError(i *requestInfo, code uint32, summary, cause string) *wt.WriteError {
	return &wt.WriteError{
		Code:    code,
		Summary: summary,
		Cause:   cause,

		Node:      i.transmitter,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),
	}
}

func (m *messageBuilder) buildWriteInitiated(i *requestInfo) *wt.WriteInitiated {
	return &wt.WriteInitiated{
		Node:      i.transmitter,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),
	}
}

func (m *messageBuilder) buildWriteSkipped(i *requestInfo, reason string) *wt.WriteSkipped {
	return &wt.WriteSkipped{
		Node:      i.transmitter,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),
		Reason:    reason,
	}
}

func (m *messageBuilder) buildWriteSent(i *requestInfo, head types.Head, txID string) *wt.WriteSent {
	return &wt.WriteSent{
		Node:      i.transmitter,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),

		TxId: txID,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,
	}
}

func (m *messageBuilder) buildWriteConfirmed(i *requestInfo, head types.Head) *wt.WriteConfirmed {
	return &wt.WriteConfirmed{
		Node:      i.transmitter,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,

		ReportId:      uint32(i.reportInfo.reportID),
		ReportContext: i.reportInfo.reportContext,
		Report:        i.reportInfo.report,
		SignersNum:    i.reportInfo.signersNum,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,
	}
}
