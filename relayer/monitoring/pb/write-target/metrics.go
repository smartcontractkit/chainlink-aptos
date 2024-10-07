package write_target

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel/metric"
	"strconv"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new struct for metrics
type Metrics struct {
	// Define on WriteConfirmed metrics
	writeConfirmed struct {
		// write_target_write_confirmed_count
		count metric.Int64Counter
		// write_target_write_confirmed_block_timestamp
		blockTimestamp metric.Int64Gauge
		// write_target_write_confirmed_block_number
		blockNumber metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error
	m.writeConfirmed.count, err = meter.Int64Counter("write_target_write_confirmed_count")
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.writeConfirmed.blockTimestamp, err = meter.Int64Gauge("write_target_write_confirmed_block_timestamp")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeConfirmed.blockNumber, err = meter.Int64Gauge("write_target_write_confirmed_block_number")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnWriteConfirmed(ctx context.Context, msg *WriteConfirmed) error {
	// Count events
	m.writeConfirmed.count.Add(ctx, 1)

	// Block timestamp
	m.writeConfirmed.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp))

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.writeConfirmed.blockNumber.Record(ctx, blockHeightVal)

	return nil
}
