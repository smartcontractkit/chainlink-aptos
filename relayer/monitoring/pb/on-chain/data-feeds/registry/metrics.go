package registry

import (
	"context"
	"fmt"
	"go.opentelemetry.io/otel/metric"
	"strconv"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new struct for metrics
type Metrics struct {
	// Define on FeedUpdated metrics
	feedUpdated struct {
		// on_chain_data_feeds_registry_feed_updated_count
		count metric.Int64Counter
		// on_chain_data_feeds_registry_feed_updated_timestamp
		timestamp metric.Int64Gauge
		// on_chain_data_feeds_registry_feed_updated_benchmark
		benchmark metric.Int64Gauge
		// on_chain_data_feeds_registry_feed_updated_block_timestamp
		blockTimestamp metric.Int64Gauge
		// on_chain_data_feeds_registry_feed_updated_block_number
		blockNumber metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error
	m.feedUpdated.count, err = meter.Int64Counter("on_chain_data_feeds_registry_feed_updated_count")
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.feedUpdated.timestamp, err = meter.Int64Gauge("on_chain_data_feeds_registry_feed_updated_timestamp")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.benchmark, err = meter.Int64Gauge("on_chain_data_feeds_registry_feed_updated_benchmark")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.blockTimestamp, err = meter.Int64Gauge("on_chain_data_feeds_registry_feed_updated_block_timestamp")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.blockNumber, err = meter.Int64Gauge("on_chain_data_feeds_registry_feed_updated_block_number")
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnFeedUpdated(ctx context.Context, msg *FeedUpdated) error {
	// Count events
	m.feedUpdated.count.Add(ctx, 1)

	// Timestamp
	m.feedUpdated.timestamp.Record(ctx, int64(msg.Timestamp))

	// Benchmark
	m.feedUpdated.benchmark.Record(ctx, int64(msg.Benchmark))

	// Block timestamp
	m.feedUpdated.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp))

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.feedUpdated.blockNumber.Record(ctx, blockHeightVal)

	return nil
}
