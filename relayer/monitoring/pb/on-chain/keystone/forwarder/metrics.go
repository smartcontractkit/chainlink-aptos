package forwarder

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel/metric"
	"strconv"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new struct for metrics
type Metrics struct {
	// Define on ReportProcessed metrics
	reportProcessed struct {
		// on_chain_keystone_forwarder_report_processed_count
		count metric.Int64Counter
		// on_chain_keystone_forwarder_report_processed_block_timestamp
		blockTimestamp metric.Int64Gauge
		// on_chain_keystone_forwarder_report_processed_block_number
		blockNumber metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error
	m.reportProcessed.count, err = meter.Int64Counter("on_chain_keystone_forwarder_report_processed_count")
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.reportProcessed.blockTimestamp, err = meter.Int64Gauge("on_chain_keystone_forwarder_report_processed_block_timestamp")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.reportProcessed.blockNumber, err = meter.Int64Gauge("on_chain_keystone_forwarder_report_processed_block_number")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnReportProcessed(ctx context.Context, msg *ReportProcessed) error {
	// Count events
	m.reportProcessed.count.Add(ctx, 1)

	// Block timestamp
	m.reportProcessed.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp))

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.reportProcessed.blockNumber.Record(ctx, blockHeightVal)

	return nil
}
