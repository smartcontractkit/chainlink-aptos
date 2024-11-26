package registry

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
	return fmt.Sprintf("data_feeds_on_chain_registry_%s", name)
}

// Define metrics configuration
var (
	feedUpdated = struct {
		// common
		count             utils.MetricInfo
		capTimestampStart utils.MetricInfo
		capTimestampEmit  utils.MetricInfo
		capDuration       utils.MetricInfo // ts.emit - ts.start
		// specific to FeedUpdated
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
		capTimestampStart: utils.MetricInfo{
			Name:        ns("feed_updated_cap_timestamp_start"),
			Unit:        "ms",
			Description: "The timestamp (local) at capability exec start that resulted in message: 'data-feeds.on-chain.registry.FeedUpdated' emit",
		},
		capTimestampEmit: utils.MetricInfo{
			Name:        ns("feed_updated_cap_timestamp_emit"),
			Unit:        "ms",
			Description: "The timestamp (local) at message: 'data-feeds.on-chain.registry.FeedUpdated' emit",
		},
		capDuration: utils.MetricInfo{
			Name:        ns("feed_updated_cap_duration"),
			Unit:        "ms",
			Description: "The duration (local) since capability exec start for message: 'data-feeds.on-chain.registry.FeedUpdated' emit",
		},
		observationsTimestamp: utils.MetricInfo{
			Name:        ns("feed_updated_observations_timestamp"),
			Unit:        "ms",
			Description: "The observations timestamp for the latest confirmed update (as reported)",
		},
		benchmark: utils.MetricInfo{
			Name:        ns("feed_updated_benchmark"),
			Unit:        "",
			Description: "The benchmark value for the latest confirmed update (as reported)",
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
		// common
		count             metric.Int64Counter
		capTimestampStart metric.Int64Gauge
		capTimestampEmit  metric.Int64Gauge
		capDuration       metric.Int64Gauge // ts.emit - ts.start
		// specific to FeedUpdated
		observationsTimestamp metric.Int64Gauge
		benchmark             metric.Float64Gauge
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

	m.feedUpdated.capTimestampStart, err = feedUpdated.capTimestampStart.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.capTimestampEmit, err = feedUpdated.capTimestampEmit.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.capDuration, err = feedUpdated.capDuration.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.observationsTimestamp, err = feedUpdated.observationsTimestamp.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.feedUpdated.benchmark, err = feedUpdated.benchmark.NewFloat64Gauge(meter)
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

func (m *Metrics) OnFeedUpdated(ctx context.Context, msg *FeedUpdated, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.feedUpdated.count.Add(ctx, 1, attrs)

	// Timestamp events
	start, emit := msg.MetaCapabilityTimestampStart, msg.MetaCapabilityTimestampEmit
	m.feedUpdated.capTimestampStart.Record(ctx, int64(start), attrs)
	m.feedUpdated.capTimestampEmit.Record(ctx, int64(emit), attrs)
	m.feedUpdated.capDuration.Record(ctx, int64(emit-start), attrs)

	// Timestamp
	m.feedUpdated.observationsTimestamp.Record(ctx, int64(msg.ObservationsTimestamp), attrs)

	// Benchmark
	m.feedUpdated.benchmark.Record(ctx, msg.BenchmarkVal, attrs)

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

// Attributes returns the attributes for the FeedUpdated message to be used in metrics
func (m *FeedUpdated) Attributes() []attribute.KeyValue {
	context := utils.ExecutionMetadata{
		// Execution Context - Source
		SourceId: m.MetaSourceId,
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
		attribute.String("feed_id", m.FeedId),

		// TODO: do we need these attributes? (available in WriteConfirmed)
		// attribute.String("node", m.Node),
		// attribute.String("forwarder", m.Forwarder),
		// attribute.String("receiver", m.Receiver),
		// attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
		// attribute.String("transmitter", m.Transmitter),
	}

	return append(attrs, context.Attributes()...)
}
