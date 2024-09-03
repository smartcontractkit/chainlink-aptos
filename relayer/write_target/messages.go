package write_target

import (
	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

type messageBuilder struct{}

func (m *messageBuilder) buildWriteError(ctx requestContext, code uint32, summary, cause string) *wt.WriteError {
	return &wt.WriteError{
		Code:    code,
		Summary: summary,
		Cause:   cause,

		Forwarder:   ctx.forwarder,
		Receiver:    ctx.receiver,
		Transmitter: ctx.transmitter,
		ReportId:    uint32(ctx.reportID),
	}
}

func (m *messageBuilder) buildWriteInitiated(ctx requestContext) *wt.WriteInitiated {
	return &wt.WriteInitiated{
		Forwarder:   ctx.forwarder,
		Receiver:    ctx.receiver,
		Transmitter: ctx.transmitter,
		ReportId:    uint32(ctx.reportID),
	}
}

func (m *messageBuilder) buildWriteSkipped(ctx requestContext, reason string) *wt.WriteSkipped {
	return &wt.WriteSkipped{
		Forwarder:   ctx.forwarder,
		Receiver:    ctx.receiver,
		Transmitter: ctx.transmitter,
		ReportId:    uint32(ctx.reportID),
		Reason:      reason,
	}
}

func (m *messageBuilder) buildWriteSent(ctx requestContext, txHash string) *wt.WriteSent {
	return &wt.WriteSent{
		Forwarder:   ctx.forwarder,
		Receiver:    ctx.receiver,
		Transmitter: ctx.transmitter,
		ReportId:    uint32(ctx.reportID),

		TxHash: txHash,
		// TODO: is this metadata necessary here? (hard to source from CW -> TXM)
		XMetadata:     []byte{},
		XMetadataType: "aptos-tx-sent-metadata",
	}
}
