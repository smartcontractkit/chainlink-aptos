package write_target

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

// Define metrics configuration
var (
	writeConfirmed = struct {
		count          MetricConfig
		blockTimestamp MetricConfig
		blockNumber    MetricConfig
		signersNumber  MetricConfig
	}{
		count: MetricConfig{
			name:        "keystone_write_target_write_confirmed_count",
			unit:        "",
			description: "The count of message: 'keystone.write-target.WriteConfirmed' emitted",
		},
		blockTimestamp: MetricConfig{
			name:        "keystone_write_target_write_confirmed_block_timestamp",
			unit:        "ms",
			description: "The block timestamp for latest confirmed write (as observed)",
		},
		blockNumber: MetricConfig{
			name:        "keystone_write_target_write_confirmed_block_number",
			unit:        "",
			description: "The block number for latest confirmed write (as observed)",
		},
		signersNumber: MetricConfig{
			name:        "keystone_write_target_write_confirmed_signers_number",
			unit:        "",
			description: "The number of signers attached to the processed and confirmed write request",
		},
	}
)

// Define a new struct for metrics
type Metrics struct {
	// Define on WriteConfirmed metrics
	writeConfirmed struct {
		count          metric.Int64Counter
		blockTimestamp metric.Int64Gauge
		blockNumber    metric.Int64Gauge
		signersNumber  metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error

	mc := writeConfirmed.count
	m.writeConfirmed.count, err = meter.Int64Counter(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	mc = writeConfirmed.blockTimestamp
	m.writeConfirmed.blockTimestamp, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = writeConfirmed.blockNumber
	m.writeConfirmed.blockNumber, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = writeConfirmed.signersNumber
	m.writeConfirmed.signersNumber, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnWriteConfirmed(ctx context.Context, msg *WriteConfirmed) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		attribute.String("node", msg.Node),
		attribute.String("forwarder", msg.Forwarder),
		attribute.String("receiver", msg.Receiver),
		attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
		attribute.String("transmitter", msg.Transmitter),
		attribute.Bool("success", msg.Success),
	)

	// Count events
	m.writeConfirmed.count.Add(ctx, 1, attrs)

	// Signers number
	m.writeConfirmed.signersNumber.Record(ctx, int64(msg.SignersNum), attrs)

	// Block timestamp
	m.writeConfirmed.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp), attrs)

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.writeConfirmed.blockNumber.Record(ctx, blockHeightVal, attrs)

	return nil
}
