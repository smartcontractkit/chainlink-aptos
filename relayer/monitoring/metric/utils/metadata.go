package utils

import (
	"go.opentelemetry.io/otel/attribute"
)

// TODO: Refactor as a proto referenced from the other proto files (telemetry messages)
type ExecutionMetadata struct {
	// Execution Context - Chain
	ChainName      string
	NetworkName    string
	NetworkChainId string
	// Execution Context - Workflow (capabilities.RequestMetadata)
	WorkflowId               string
	WorkflowOwner            string
	WorkflowExecutionId      string
	WorkflowName             string
	WorkflowDonId            uint32
	WorkflowDonConfigVersion uint32
	ReferenceId              string
	// Execution Context - Capability
	CapabilityType string
	CapabilityId   string
}

// Attributes returns common attributes used for metrics
func (m ExecutionMetadata) Attributes() []attribute.KeyValue {
	return []attribute.KeyValue{
		// Execution Context - Chain
		attribute.String("chain_name", m.ChainName),
		attribute.String("network_name", m.NetworkName),
		attribute.String("network_chain_id", m.NetworkChainId),
		// Execution Context - Workflow (capabilities.RequestMetadata)
		attribute.String("workflow_id", m.WorkflowId),
		attribute.String("workflow_owner", m.WorkflowOwner),
		// Notice: WorkflowExecutionId is not used by metrics (skipped b/c high cardinality)
		attribute.String("workflow_name", m.WorkflowName),
		attribute.Int64("workflow_don_id", int64(m.WorkflowDonId)),
		attribute.Int64("workflow_don_config_version", int64(m.WorkflowDonConfigVersion)),
		attribute.String("reference_id", m.ReferenceId),
		// Execution Context - Capability
		attribute.String("capability_type", m.CapabilityType),
		attribute.String("capability_id", m.CapabilityId),
	}
}
