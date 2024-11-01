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
		attribute.String("chain_name", valOrUnknown(m.ChainName)),
		attribute.String("network_name", valOrUnknown(m.NetworkName)),
		attribute.String("network_chain_id", valOrUnknown(m.NetworkChainId)),
		// Execution Context - Workflow (capabilities.RequestMetadata)
		attribute.String("workflow_id", valOrUnknown(m.WorkflowId)),
		attribute.String("workflow_owner", valOrUnknown(m.WorkflowOwner)),
		// Notice: WorkflowExecutionId is not used by metrics (skipped b/c high cardinality)
		attribute.String("workflow_name", valOrUnknown(m.WorkflowName)),
		attribute.Int64("workflow_don_id", int64(m.WorkflowDonId)),
		attribute.Int64("workflow_don_config_version", int64(m.WorkflowDonConfigVersion)),
		attribute.String("reference_id", valOrUnknown(m.ReferenceId)),
		// Execution Context - Capability
		attribute.String("capability_type", valOrUnknown(m.CapabilityType)),
		attribute.String("capability_id", valOrUnknown(m.CapabilityId)),
	}
}

// This is needed to avoid issues during exporting OTel metrics to Prometheus
// For more details see https://smartcontract-it.atlassian.net/browse/INFOPLAT-1349
// valOrUnknown returns the value if it is not empty, otherwise it returns "unknown"
func valOrUnknown(val string) string {
	if val == "" {
		return "unknown"
	}
	return val
}
