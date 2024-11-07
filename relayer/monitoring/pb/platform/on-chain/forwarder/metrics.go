package forwarder

import (
	"context"
	"fmt"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/metric/utils"
)

// ns returns a namespaced metric name
func ns(name string) string {
	return fmt.Sprintf("platform_on_chain_forwarder_%s", name)
}

// Define metrics configuration
var (
	reportProcessed = struct {
		count          utils.MetricInfo
		blockTimestamp utils.MetricInfo
		blockNumber    utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("report_processed_count"),
			Unit:        "",
			Description: "The count of message: 'platform.on-chain.forwarder.ReportProcessed' emitted",
		},
		blockTimestamp: utils.MetricInfo{
			Name:        ns("report_processed_block_timestamp"),
			Unit:        "ms",
			Description: "The block timestamp at the latest confirmed write (as observed)",
		},
		blockNumber: utils.MetricInfo{
			Name:        ns("report_processed_block_number"),
			Unit:        "",
			Description: "The block number at the latest confirmed write (as observed)",
		},
	}
)

// Define a new struct for metrics
type Metrics struct {
	// Define on ReportProcessed metrics
	reportProcessed struct {
		count          metric.Int64Counter
		blockTimestamp metric.Int64Gauge
		blockNumber    metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error

	m.reportProcessed.count, err = reportProcessed.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.reportProcessed.blockTimestamp, err = reportProcessed.blockTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.reportProcessed.blockNumber, err = reportProcessed.blockNumber.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnReportProcessed(ctx context.Context, msg *ReportProcessed, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.reportProcessed.count.Add(ctx, 1, attrs)

	// Block timestamp
	m.reportProcessed.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp), attrs)

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.reportProcessed.blockNumber.Record(ctx, blockHeightVal, attrs)

	return nil
}

// Attributes returns the attributes for the ReportProcessed message to be used in metrics
func (m *ReportProcessed) Attributes() []attribute.KeyValue {
	context := utils.ExecutionMetadata{
		// Execution Context - Chain
		ChainFamilyName: m.MetaChainFamilyName,
		ChainId:         m.MetaChainId,
		NetworkName:     m.MetaNetworkName,
		NetworkNameFull: m.MetaNetworkNameFull,
		// Execution Context - Workflow (capabilities.RequestMetadata)
		WorkflowId:               m.MetaWorkflowId,
		WorkflowOwner:            m.MetaWorkflowOwner,
		WorkflowExecutionId:      m.MetaWorkflowExecutionId,
		WorkflowName:             m.MetaWorkflowName,
		WorkflowDonId:            m.MetaWorkflowDonId,
		WorkflowDonConfigVersion: m.MetaWorkflowDonConfigVersion,
		ReferenceId:              m.MetaReferenceId,
		// Execution Context - Capability
		CapabilityType: m.MetaCapabilityType,
		CapabilityId:   m.MetaCapabilityId,
	}

	attrs := []attribute.KeyValue{
		// TODO: do we need these attributes? (available in WriteConfirmed)
		// attribute.String("node", m.Node),
		// attribute.String("forwarder", m.Forwarder),
		attribute.String("receiver", m.Receiver),
		attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
		// attribute.String("transmitter", m.Transmitter),
		attribute.Bool("success", m.Success),
	}

	return append(attrs, context.Attributes()...)
}
