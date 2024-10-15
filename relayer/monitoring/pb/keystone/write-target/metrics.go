package write_target

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
	return fmt.Sprintf("keystone_write_target_%s", name)
}

// Define metrics configuration
var (
	writeInitiated = struct {
		count utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_initiated_count"),
			Unit:        "",
			Description: "The count of message: 'keystone.write-target.WriteInitiated' emitted",
		},
	}
	writeError = struct {
		count utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_error_count"),
			Unit:        "",
			Description: "The count of message: 'keystone.write-target.WriteError' emitted",
		},
	}
	writeSent = struct {
		count          utils.MetricInfo
		blockTimestamp utils.MetricInfo
		blockNumber    utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_sent_count"),
			Unit:        "",
			Description: "The count of message: 'keystone.write-target.WriteSent' emitted",
		},
		blockTimestamp: utils.MetricInfo{
			Name:        ns("write_sent_block_timestamp"),
			Unit:        "ms",
			Description: "The block timestamp for latest sent write (as observed)",
		},
		blockNumber: utils.MetricInfo{
			Name:        ns("write_sent_block_number"),
			Unit:        "",
			Description: "The block number for latest sent write (as observed)",
		},
	}
	writeConfirmed = struct {
		count          utils.MetricInfo
		blockTimestamp utils.MetricInfo
		blockNumber    utils.MetricInfo
		signersNumber  utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_confirmed_count"),
			Unit:        "",
			Description: "The count of message: 'keystone.write-target.WriteConfirmed' emitted",
		},
		blockTimestamp: utils.MetricInfo{
			Name:        ns("write_confirmed_block_timestamp"),
			Unit:        "ms",
			Description: "The block timestamp for latest confirmed write (as observed)",
		},
		blockNumber: utils.MetricInfo{
			Name:        ns("write_confirmed_block_number"),
			Unit:        "",
			Description: "The block number for latest confirmed write (as observed)",
		},
		signersNumber: utils.MetricInfo{
			Name:        ns("write_confirmed_signers_number"),
			Unit:        "",
			Description: "The number of signers attached to the processed and confirmed write request",
		},
	}
)

// Define a new struct for metrics
type Metrics struct {
	// Define on WriteInitiated metrics
	writeInitiated struct {
		count metric.Int64Counter
	}
	// Define on WriteError metrics
	writeError struct {
		count metric.Int64Counter
	}
	// Define on WriteSent metrics
	writeSent struct {
		count          metric.Int64Counter
		blockTimestamp metric.Int64Gauge
		blockNumber    metric.Int64Gauge
	}
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

	// WriteInitiated
	m.writeInitiated.count, err = writeInitiated.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	// WriteError
	m.writeError.count, err = writeError.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	// WriteSent
	m.writeSent.count, err = writeSent.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.writeSent.blockTimestamp, err = writeSent.blockTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeSent.blockNumber, err = writeSent.blockNumber.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	// WriteConfirmed
	m.writeConfirmed.count, err = writeConfirmed.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.writeConfirmed.blockTimestamp, err = writeConfirmed.blockTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeConfirmed.blockNumber, err = writeConfirmed.blockNumber.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeConfirmed.signersNumber, err = writeConfirmed.signersNumber.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnWriteInitiated(ctx context.Context, msg *WriteInitiated) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		attribute.String("node", msg.Node),
		attribute.String("forwarder", msg.Forwarder),
		attribute.String("receiver", msg.Receiver),
		attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
	)

	// Count events
	m.writeConfirmed.count.Add(ctx, 1, attrs)
	return nil
}

func (m *Metrics) OnWriteError(ctx context.Context, msg *WriteError) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		attribute.String("node", msg.Node),
		attribute.String("forwarder", msg.Forwarder),
		attribute.String("receiver", msg.Receiver),
		attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
	)

	// Count events
	m.writeError.count.Add(ctx, 1, attrs)
	return nil
}

func (m *Metrics) OnWriteSent(ctx context.Context, msg *WriteSent) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		attribute.String("node", msg.Node),
		attribute.String("forwarder", msg.Forwarder),
		attribute.String("receiver", msg.Receiver),
		attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
	)

	// Count events
	m.writeSent.count.Add(ctx, 1, attrs)

	// Block timestamp
	m.writeSent.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp), attrs)

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.writeSent.blockNumber.Record(ctx, blockHeightVal, attrs)
	return nil
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
