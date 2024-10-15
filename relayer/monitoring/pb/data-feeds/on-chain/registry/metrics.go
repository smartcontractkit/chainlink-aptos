package registry

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/metric/utils"
)

// ns returns a namespaced metric name
func ns(name string) string {
	return fmt.Sprintf("data_feeds_on_chain_registry_%s", name)
}

// Define metrics configuration
var (
	feedUpdated = struct {
		count                 utils.MetricInfo
		observationsTimestamp utils.MetricInfo
		benchmark             utils.MetricInfo
		blockTimestamp        utils.MetricInfo
		blockNumber           utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("feed_updated_count"),
			Unit:        "",
			Description: "The count of message: 'data-feeds.on-chain.registry.FeedUpdated' emitted",
		},
		observationsTimestamp: utils.MetricInfo{
			Name:        ns("feed_updated_observations_timestamp"),
			Unit:        "ms",
			Description: "The observations timestamp for the latest confirmed update (as reported)",
		},
		benchmark: utils.MetricInfo{
			Name:        ns("feed_updated_benchmark"),
			Unit:        "",
			Description: "The benchmark value for the latest confirmed update (as reported)",,
		},
		blockTimestamp: utils.MetricInfo{
			Name:        ns("feed_updated_block_timestamp"),
			Unit:        "ms",
			Description: "The block timestamp at the latest confirmed update (as observed)",
		},
		blockNumber: utils.MetricInfo{
			Name:        ns("feed_updated_block_number"),
			Unit:        "",
			Description: "The block number at the latest confirmed update (as observed)",
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

	m.feedUpdated.count, err = feedUpdated.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.feedUpdated.observationsTimestamp, err = feedUpdated.observationsTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.benchmark, err = feedUpdated.benchmark.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.blockTimestamp, err = feedUpdated.blockTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.blockNumber, err = feedUpdated.blockNumber.NewInt64Gauge(meter)
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
