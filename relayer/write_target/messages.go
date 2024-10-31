package write_target

import (
	"encoding/hex"

	"github.com/smartcontractkit/chainlink-common/pkg/types"

	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/platform/write-target"
)

type messageBuilder struct{}

func (m *messageBuilder) buildWriteError(i *requestInfo, code uint32, summary, cause string) *wt.WriteError {
	return &wt.WriteError{
		Code:    code,
		Summary: summary,
		Cause:   cause,

		Node:      i.node,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),

		// Execution Context - Chain
		// TODO: Add chain info

		// Execution Context - Workflow (capabilities.RequestMetadata)
		MetaWorkflowId:               i.request.Metadata.WorkflowID,
		MetaWorkflowOwner:            i.request.Metadata.WorkflowOwner,
		MetaWorkflowExecutionId:      i.request.Metadata.WorkflowExecutionID,
		MetaWorkflowName:             i.request.Metadata.WorkflowName,
		MetaWorkflowDonId:            i.request.Metadata.WorkflowDonID,
		MetaWorkflowDonConfigVersion: i.request.Metadata.WorkflowDonConfigVersion,
		MetaReferenceId:              i.request.Metadata.ReferenceID,

		// Execution Context - Capability
		MetaCapabilityType: string(i.capInfo.CapabilityType),
		MetaCapabilityId:   i.capInfo.ID,
	}
}

func (m *messageBuilder) buildWriteInitiated(i *requestInfo) *wt.WriteInitiated {
	return &wt.WriteInitiated{
		Node:      i.node,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),

		// Execution Context - Chain
		// TODO: Add chain info

		// Execution Context - Workflow (capabilities.RequestMetadata)
		MetaWorkflowId:               i.request.Metadata.WorkflowID,
		MetaWorkflowOwner:            i.request.Metadata.WorkflowOwner,
		MetaWorkflowExecutionId:      i.request.Metadata.WorkflowExecutionID,
		MetaWorkflowName:             i.request.Metadata.WorkflowName,
		MetaWorkflowDonId:            i.request.Metadata.WorkflowDonID,
		MetaWorkflowDonConfigVersion: i.request.Metadata.WorkflowDonConfigVersion,
		MetaReferenceId:              i.request.Metadata.ReferenceID,

		// Execution Context - Capability
		MetaCapabilityType: string(i.capInfo.CapabilityType),
		MetaCapabilityId:   i.capInfo.ID,
	}
}

func (m *messageBuilder) buildWriteSkipped(i *requestInfo, reason string) *wt.WriteSkipped {
	return &wt.WriteSkipped{
		Node:      i.node,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),
		Reason:    reason,

		// Execution Context - Chain
		// TODO: Add chain info

		// Execution Context - Workflow (capabilities.RequestMetadata)
		MetaWorkflowId:               i.request.Metadata.WorkflowID,
		MetaWorkflowOwner:            i.request.Metadata.WorkflowOwner,
		MetaWorkflowExecutionId:      i.request.Metadata.WorkflowExecutionID,
		MetaWorkflowName:             i.request.Metadata.WorkflowName,
		MetaWorkflowDonId:            i.request.Metadata.WorkflowDonID,
		MetaWorkflowDonConfigVersion: i.request.Metadata.WorkflowDonConfigVersion,
		MetaReferenceId:              i.request.Metadata.ReferenceID,

		// Execution Context - Capability
		MetaCapabilityType: string(i.capInfo.CapabilityType),
		MetaCapabilityId:   i.capInfo.ID,
	}
}

func (m *messageBuilder) buildWriteSent(i *requestInfo, head types.Head, txID string) *wt.WriteSent {
	return &wt.WriteSent{
		Node:      i.node,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,
		ReportId:  uint32(i.reportInfo.reportID),

		TxId: txID,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,

		// Execution Context - Chain
		// TODO: Add chain info

		// Execution Context - Workflow (capabilities.RequestMetadata)
		MetaWorkflowId:               i.request.Metadata.WorkflowID,
		MetaWorkflowOwner:            i.request.Metadata.WorkflowOwner,
		MetaWorkflowExecutionId:      i.request.Metadata.WorkflowExecutionID,
		MetaWorkflowName:             i.request.Metadata.WorkflowName,
		MetaWorkflowDonId:            i.request.Metadata.WorkflowDonID,
		MetaWorkflowDonConfigVersion: i.request.Metadata.WorkflowDonConfigVersion,
		MetaReferenceId:              i.request.Metadata.ReferenceID,

		// Execution Context - Capability
		MetaCapabilityType: string(i.capInfo.CapabilityType),
		MetaCapabilityId:   i.capInfo.ID,
	}
}

func (m *messageBuilder) buildWriteConfirmed(i *requestInfo, head types.Head) *wt.WriteConfirmed {
	return &wt.WriteConfirmed{
		Node:      i.node,
		Forwarder: i.forwarder,
		Receiver:  i.receiver,

		ReportId:      uint32(i.reportInfo.reportID),
		ReportContext: i.reportInfo.reportContext,
		Report:        i.reportInfo.report,
		SignersNum:    i.reportInfo.signersNum,

		BlockHash:      hex.EncodeToString(head.Hash),
		BlockHeight:    head.Height,
		BlockTimestamp: head.Timestamp,

		// Transmission Info
		Transmitter: i.reportTransmissionState.Transmitter,
		Success:     i.reportTransmissionState.Success,

		// Execution Context - Chain
		// TODO: Add chain info

		// Execution Context - Workflow (capabilities.RequestMetadata)
		MetaWorkflowId:               i.request.Metadata.WorkflowID,
		MetaWorkflowOwner:            i.request.Metadata.WorkflowOwner,
		MetaWorkflowExecutionId:      i.request.Metadata.WorkflowExecutionID,
		MetaWorkflowName:             i.request.Metadata.WorkflowName,
		MetaWorkflowDonId:            i.request.Metadata.WorkflowDonID,
		MetaWorkflowDonConfigVersion: i.request.Metadata.WorkflowDonConfigVersion,
		MetaReferenceId:              i.request.Metadata.ReferenceID,

		// Execution Context - Capability
		MetaCapabilityType: string(i.capInfo.CapabilityType),
		MetaCapabilityId:   i.capInfo.ID,
	}
}
