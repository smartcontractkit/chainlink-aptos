package forwarder

import (
	"context"
	"fmt"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new struct for metrics configuration
type MetricConfig struct {
	name        string
	unit        string
	description string
}

// ns returns a namespaced metric name
func ns(name string) string {
	return fmt.Sprintf("keystone_on_chain_forwarder_%s", name)
}

// Define metrics configuration
var (
	reportProcessed = struct {
		count          MetricConfig
		blockTimestamp MetricConfig
		blockNumber    MetricConfig
	}{
		count: MetricConfig{
			name:        ns("report_processed_count"),
			unit:        "",
			description: "The count of message: 'keystone.on-chain.forwarder.ReportProcessed' emitted",
		},
		blockTimestamp: MetricConfig{
			name:        ns("report_processed_block_timestamp"),
			unit:        "ms",
			description: "The block timestamp for latest confirmed write (as observed)",
		},
		blockNumber: MetricConfig{
			name:        ns("report_processed_block_number"),
			unit:        "",
			description: "The block number for latest confirmed write (as observed)",
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

	mc := reportProcessed.count
	m.reportProcessed.count, err = meter.Int64Counter(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	mc = reportProcessed.blockTimestamp
	m.reportProcessed.blockTimestamp, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = reportProcessed.blockNumber
	m.reportProcessed.blockNumber, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnReportProcessed(ctx context.Context, msg *ReportProcessed) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		// TODO: do we need these attributes? (available in WriteConfirmed)
		// attribute.String("node", msg.Node),
		// attribute.String("forwarder", msg.Forwarder),
		attribute.String("receiver", msg.Receiver),
		attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
		// attribute.String("transmitter", msg.Transmitter),
		attribute.Bool("success", msg.Success),
	)

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
