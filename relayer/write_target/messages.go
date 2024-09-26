package write_target

import (
	"encoding/hex"

	"github.com/smartcontractkit/chainlink-common/pkg/types"

	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

type messageBuilder struct{}

func (m *messageBuilder) buildWriteError(ctx requestContext, code uint32, summary, cause string) *wt.WriteError {
	return &wt.WriteError{
		Code:    code,
		Summary: summary,
		Cause:   cause,

		Node:      ctx.transmitter,
		Forwarder: ctx.forwarder,
		Receiver:  ctx.receiver,
		ReportId:  uint32(ctx.reportInfo.reportID),
	}
}

func (m *messageBuilder) buildWriteInitiated(ctx requestContext) *wt.WriteInitiated {
	return &wt.WriteInitiated{
		Node:      ctx.transmitter,
		Forwarder: ctx.forwarder,
		Receiver:  ctx.receiver,
		ReportId:  uint32(ctx.reportInfo.reportID),
	}
}

func (m *messageBuilder) buildWriteSkipped(ctx requestContext, reason string) *wt.WriteSkipped {
	return &wt.WriteSkipped{
		Node:      ctx.transmitter,
		Forwarder: ctx.forwarder,
		Receiver:  ctx.receiver,
		ReportId:  uint32(ctx.reportInfo.reportID),
		Reason:    reason,
	}
}

func (m *messageBuilder) buildWriteSent(ctx requestContext, head types.Head, txID string) *wt.WriteSent {
	return &wt.WriteSent{
		Node:      ctx.transmitter,
		Forwarder: ctx.forwarder,
		Receiver:  ctx.receiver,
		ReportId:  uint32(ctx.reportInfo.reportID),

		TxId: txID,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,
	}
}

func (m *messageBuilder) buildWriteConfirmed(ctx requestContext, head types.Head) *wt.WriteConfirmed {
	return &wt.WriteConfirmed{
		Node:      ctx.transmitter,
		Forwarder: ctx.forwarder,
		Receiver:  ctx.receiver,

		ReportId:      uint32(ctx.reportInfo.reportID),
		ReportContext: ctx.reportInfo.reportContext,
		Report:        ctx.reportInfo.report,
		SignersNum:    ctx.reportInfo.signersNum,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,
	}
}
