package utils

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new struct for metrics information
type MetricInfo struct {
	Name        string
	Unit        string
	Description string
}

// NewInt64Counter creates a new Int64Counter metric
func (m MetricInfo) NewInt64Counter(meter metric.Meter) (metric.Int64Counter, error) {
	return meter.Int64Counter(
		m.Name,
		metric.WithUnit(m.Unit),
		metric.WithDescription(m.Description),
	)
}

// NewInt64Gauge creates a new Int64Gauge metric
func (m MetricInfo) NewInt64Gauge(meter metric.Meter) (metric.Int64Gauge, error) {
	return meter.Int64Gauge(
		m.Name,
		metric.WithUnit(m.Unit),
		metric.WithDescription(m.Description),
	)
}

// CommonAttributes returns common attributes for metrics, extracted from Beholder attributes
func CommonAttributes(attrKVs ...any) []attribute.KeyValue {
	// Extract common attributes
	attrs := beholder.NewMessage([]byte{}, attrKVs...).Attrs
	meta := beholder.NewMetadata(attrs)

	// TODO: extract (hardcoded)
	chainName := "aptos"

	// Extract network name
	networkName := "unknown"
	if len(meta.NetworkName) > 0 {
		networkName = meta.NetworkName[0]
	}

	return []attribute.KeyValue{
		// Chain and network
		attribute.String("chain_name", chainName),
		attribute.String("network_name", networkName),
		attribute.String("network_chain_id", meta.NetworkChainID),

		// Deployment
		attribute.String("don_id", meta.DonID),
		attribute.String("workflow_id", meta.WorkflowID),
		attribute.String("workflow_name", meta.WorkflowName),
		attribute.String("workflow_owner_address", meta.WorkflowOwnerAddress),
		attribute.String("workflow_spec_id", meta.WorkflowSpecID),
		attribute.String("workflow_execution_id", meta.WorkflowExecutionID),

		// Capability
		attribute.String("capability_id", meta.CapabilityID),
		attribute.String("capability_version", meta.CapabilityVersion),
		attribute.String("capability_name", meta.CapabilityName),
	}
}
