package registry

import (
	"context"
	"encoding/hex"
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
	feedUpdated = struct {
		count                 MetricConfig
		observationsTimestamp MetricConfig
		benchmark             MetricConfig
		blockTimestamp        MetricConfig
		blockNumber           MetricConfig
	}{
		count: MetricConfig{
			name:        "on_chain_data_feeds_registry_feed_updated_count",
			unit:        "",
			description: "The count of message: 'on-chain.data-feeds.registry.FeedUpdated' emitted",
		},
		observationsTimestamp: MetricConfig{
			name:        "on_chain_data_feeds_registry_feed_updated_observations_timestamp",
			unit:        "ms",
			description: "",
		},
		benchmark: MetricConfig{
			name:        "on_chain_data_feeds_registry_feed_updated_benchmark",
			unit:        "",
			description: "",
		},
		blockTimestamp: MetricConfig{
			name:        "on_chain_data_feeds_registry_feed_updated_block_timestamp",
			unit:        "ms",
			description: "The block timestamp for latest confirmed write (as observed)",
		},
		blockNumber: MetricConfig{
			name:        "on_chain_data_feeds_registry_feed_updated_block_number",
			unit:        "",
			description: "The block number for latest confirmed write (as observed)",
		},
	}
)

// Define a new struct for metrics
type Metrics struct {
	// Define on FeedUpdated metrics
	feedUpdated struct {
		count                 metric.Int64Counter
		observationsTimestamp metric.Int64Gauge
		benchmark             metric.Int64Gauge
		blockTimestamp        metric.Int64Gauge
		blockNumber           metric.Int64Gauge
	}
}

func NewMetrics() (*Metrics, error) {
	// Define new metrics
	m := &Metrics{}

	meter := beholder.GetMeter()

	// Create new metrics
	var err error

	mc := feedUpdated.count
	m.feedUpdated.count, err = meter.Int64Counter(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	mc = feedUpdated.observationsTimestamp
	m.feedUpdated.observationsTimestamp, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = feedUpdated.benchmark
	m.feedUpdated.benchmark, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = feedUpdated.blockTimestamp
	m.feedUpdated.blockTimestamp, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	mc = feedUpdated.blockNumber
	m.feedUpdated.blockNumber, err = meter.Int64Gauge(
		mc.name,
		metric.WithUnit(mc.unit),
		metric.WithDescription(mc.description),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	return m, nil
}

func (m *Metrics) OnFeedUpdated(ctx context.Context, msg *FeedUpdated) error {
	// Define common attributes
	attrs := metric.WithAttributes(
		attribute.String("feed_id", hex.EncodeToString(msg.FeedId)),

		// TODO: do we need these attributes? (available in WriteConfirmed)
		// attribute.String("node", msg.Node),
		// attribute.String("forwarder", msg.Forwarder),
		// attribute.String("receiver", msg.Receiver),
		// attribute.Int64("report_id", int64(msg.ReportId)), // uint32 -> int64
		// attribute.String("transmitter", msg.Transmitter),
	)

	// Count events
	m.feedUpdated.count.Add(ctx, 1, attrs)

	// Timestamp
	m.feedUpdated.observationsTimestamp.Record(ctx, int64(msg.ObservationsTimestamp), attrs)

	// Benchmark
	m.feedUpdated.benchmark.Record(ctx, int64(msg.Benchmark), attrs)

	// Block timestamp
	m.feedUpdated.blockTimestamp.Record(ctx, int64(msg.BlockTimestamp), attrs)

	// Block number
	blockHeightVal, err := strconv.ParseInt(msg.BlockHeight, 10, 64)
	if err != nil {
		return fmt.Errorf("failed to parse block height: %w", err)
	}
	m.feedUpdated.blockNumber.Record(ctx, blockHeightVal, attrs)

	return nil
}
