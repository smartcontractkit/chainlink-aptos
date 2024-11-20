package utils

import (
	"go.opentelemetry.io/otel/attribute"
)

// TODO: Refactor as a proto referenced from the other proto files (telemetry messages)
type ExecutionMetadata struct {
	// Execution Context - Source
	SourceId string
	// Execution Context - Chain
	ChainFamilyName string
	ChainId         string
	NetworkName     string
	NetworkNameFull string
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
		// Execution Context - Source
		attribute.String("source_id", ValOrUnknown(m.SourceId)),
		// Execution Context - Chain
		attribute.String("chain_family_name", ValOrUnknown(m.ChainFamilyName)),
		attribute.String("chain_id", ValOrUnknown(m.ChainId)),
		attribute.String("network_name", ValOrUnknown(m.NetworkName)),
		attribute.String("network_name_full", ValOrUnknown(m.NetworkNameFull)),
		// Execution Context - Workflow (capabilities.RequestMetadata)
		attribute.String("workflow_id", ValOrUnknown(m.WorkflowId)),
		attribute.String("workflow_owner", ValOrUnknown(m.WorkflowOwner)),
		// Notice: WorkflowExecutionId is not used by metrics (skipped b/c high cardinality)
		attribute.String("workflow_name", ValOrUnknown(m.WorkflowName)),
		attribute.Int64("workflow_don_id", int64(m.WorkflowDonId)),
		attribute.Int64("workflow_don_config_version", int64(m.WorkflowDonConfigVersion)),
		attribute.String("reference_id", ValOrUnknown(m.ReferenceId)),
		// Execution Context - Capability
		attribute.String("capability_type", ValOrUnknown(m.CapabilityType)),
		attribute.String("capability_id", ValOrUnknown(m.CapabilityId)),
	}
}

// This is needed to avoid issues during exporting OTel metrics to Prometheus
// For more details see https://smartcontract-it.atlassian.net/browse/INFOPLAT-1349
// ValOrUnknown returns the value if it is not empty, otherwise it returns "unknown"
func ValOrUnknown(val string) string {
	if val == "" {
		return "unknown"
	}
	return val
}
