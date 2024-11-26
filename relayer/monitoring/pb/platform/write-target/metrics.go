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
	return fmt.Sprintf("platform_write_target_%s", name)
}

// Define metrics configuration
var (
	writeInitiated = struct {
		// common
		count             utils.MetricInfo
		capTimestampStart utils.MetricInfo
		capTimestampEmit  utils.MetricInfo
		capDuration       utils.MetricInfo // ts.emit - ts.start
	}{
		count: utils.MetricInfo{
			Name:        ns("write_initiated_count"),
			Unit:        "",
			Description: "The count of message: 'platform.write-target.WriteInitiated' emitted",
		},
		capTimestampStart: utils.MetricInfo{
			Name:        ns("write_initiated_cap_timestamp_start"),
			Unit:        "ms",
			Description: "The timestamp (local) at capability exec start that resulted in message: 'platform.write-target.WriteInitiated' emit",
		},
		capTimestampEmit: utils.MetricInfo{
			Name:        ns("write_initiated_cap_timestamp_emit"),
			Unit:        "ms",
			Description: "The timestamp (local) at message: 'platform.write-target.WriteInitiated' emit",
		},
		capDuration: utils.MetricInfo{
			Name:        ns("write_initiated_cap_duration"),
			Unit:        "ms",
			Description: "The duration (local) since capability exec start for message: 'platform.write-target.WriteInitiated' emit",
		},
	}
	writeError = struct {
		// common
		count             utils.MetricInfo
		capTimestampStart utils.MetricInfo
		capTimestampEmit  utils.MetricInfo
		capDuration       utils.MetricInfo // ts.emit - ts.start
	}{
		count: utils.MetricInfo{
			Name:        ns("write_error_count"),
			Unit:        "",
			Description: "The count of message: 'platform.write-target.WriteError' emitted",
		},
		capTimestampStart: utils.MetricInfo{
			Name:        ns("write_error_cap_timestamp_start"),
			Unit:        "ms",
			Description: "The timestamp (local) at capability exec start that resulted in message: 'platform.write-target.WriteError' emit",
		},
		capTimestampEmit: utils.MetricInfo{
			Name:        ns("write_error_cap_timestamp_emit"),
			Unit:        "ms",
			Description: "The timestamp (local) at message: 'platform.write-target.WriteError' emit",
		},
		capDuration: utils.MetricInfo{
			Name:        ns("write_error_cap_duration"),
			Unit:        "ms",
			Description: "The duration (local) since capability exec start for message: 'platform.write-target.WriteError' emit",
		},
	}
	writeSent = struct {
		// common
		count             utils.MetricInfo
		capTimestampStart utils.MetricInfo
		capTimestampEmit  utils.MetricInfo
		capDuration       utils.MetricInfo // ts.emit - ts.start
		// specific to WriteSent
		blockTimestamp utils.MetricInfo
		blockNumber    utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_sent_count"),
			Unit:        "",
			Description: "The count of message: 'platform.write-target.WriteSent' emitted",
		},
		capTimestampStart: utils.MetricInfo{
			Name:        ns("write_sent_cap_timestamp_start"),
			Unit:        "ms",
			Description: "The timestamp (local) at capability exec start that resulted in message: 'platform.write-target.WriteSent' emit",
		},
		capTimestampEmit: utils.MetricInfo{
			Name:        ns("write_sent_cap_timestamp_emit"),
			Unit:        "ms",
			Description: "The timestamp (local) at message: 'platform.write-target.WriteSent' emit",
		},
		capDuration: utils.MetricInfo{
			Name:        ns("write_sent_cap_duration"),
			Unit:        "ms",
			Description: "The duration (local) since capability exec start for message: 'platform.write-target.WriteSent' emit",
		},
		blockTimestamp: utils.MetricInfo{
			Name:        ns("write_sent_block_timestamp"),
			Unit:        "ms",
			Description: "The block timestamp at the latest sent write (as observed)",
		},
		blockNumber: utils.MetricInfo{
			Name:        ns("write_sent_block_number"),
			Unit:        "",
			Description: "The block number at the latest sent write (as observed)",
		},
	}
	writeConfirmed = struct {
		// common
		count             utils.MetricInfo
		capTimestampStart utils.MetricInfo
		capTimestampEmit  utils.MetricInfo
		capDuration       utils.MetricInfo // ts.emit - ts.start
		// specific to WriteSent
		blockTimestamp utils.MetricInfo
		blockNumber    utils.MetricInfo
		signersNumber  utils.MetricInfo
	}{
		count: utils.MetricInfo{
			Name:        ns("write_confirmed_count"),
			Unit:        "",
			Description: "The count of message: 'platform.write-target.WriteConfirmed' emitted",
		},
		capTimestampStart: utils.MetricInfo{
			Name:        ns("write_confirmed_cap_timestamp_start"),
			Unit:        "ms",
			Description: "The timestamp (local) at capability exec start that resulted in message: 'platform.write-target.WriteConfirmed' emit",
		},
		capTimestampEmit: utils.MetricInfo{
			Name:        ns("write_confirmed_cap_timestamp_emit"),
			Unit:        "ms",
			Description: "The timestamp (local) at message: 'platform.write-target.WriteConfirmed' emit",
		},
		capDuration: utils.MetricInfo{
			Name:        ns("write_confirmed_cap_duration"),
			Unit:        "ms",
			Description: "The duration (local) since capability exec start for message: 'platform.write-target.WriteConfirmed' emit",
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
		// common
		count             metric.Int64Counter
		capTimestampStart metric.Int64Gauge
		capTimestampEmit  metric.Int64Gauge
		capDuration       metric.Int64Gauge // ts.emit - ts.start
	}
	// Define on WriteError metrics
	writeError struct {
		// common
		count             metric.Int64Counter
		capTimestampStart metric.Int64Gauge
		capTimestampEmit  metric.Int64Gauge
		capDuration       metric.Int64Gauge // ts.emit - ts.start
	}
	// Define on WriteSent metrics
	writeSent struct {
		// common
		count             metric.Int64Counter
		capTimestampStart metric.Int64Gauge
		capTimestampEmit  metric.Int64Gauge
		capDuration       metric.Int64Gauge // ts.emit - ts.start
		// specific to WriteSent
		blockTimestamp metric.Int64Gauge
		blockNumber    metric.Int64Gauge
	}
	// Define on WriteConfirmed metrics
	writeConfirmed struct {
		// common
		count             metric.Int64Counter
		capTimestampStart metric.Int64Gauge
		capTimestampEmit  metric.Int64Gauge
		capDuration       metric.Int64Gauge // ts.emit - ts.start
		// specific to WriteConfirmed
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

	m.writeInitiated.capTimestampStart, err = writeInitiated.capTimestampStart.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeInitiated.capTimestampEmit, err = writeInitiated.capTimestampEmit.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeInitiated.capDuration, err = writeInitiated.capDuration.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	// WriteError
	m.writeError.count, err = writeError.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.writeError.capTimestampStart, err = writeError.capTimestampStart.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeError.capTimestampEmit, err = writeError.capTimestampEmit.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeError.capDuration, err = writeError.capDuration.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	// WriteSent
	m.writeSent.count, err = writeSent.count.NewInt64Counter(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new counter: %w", err)
	}

	m.writeSent.capTimestampStart, err = writeSent.capTimestampStart.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeSent.capTimestampEmit, err = writeSent.capTimestampEmit.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeSent.capDuration, err = writeSent.capDuration.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
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

	m.writeConfirmed.capTimestampStart, err = writeConfirmed.capTimestampStart.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeConfirmed.capTimestampEmit, err = writeConfirmed.capTimestampEmit.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
	}

	m.writeConfirmed.capDuration, err = writeConfirmed.capDuration.NewInt64Gauge(meter)
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge: %w", err)
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

func (m *Metrics) OnWriteInitiated(ctx context.Context, msg *WriteInitiated, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.writeInitiated.count.Add(ctx, 1, attrs)

	// Timestamp events
	start, emit := msg.MetaCapabilityTimestampStart, msg.MetaCapabilityTimestampEmit
	m.writeInitiated.capTimestampStart.Record(ctx, int64(start), attrs)
	m.writeInitiated.capTimestampEmit.Record(ctx, int64(emit), attrs)
	m.writeInitiated.capDuration.Record(ctx, int64(emit-start), attrs)
	return nil
}

func (m *Metrics) OnWriteError(ctx context.Context, msg *WriteError, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.writeError.count.Add(ctx, 1, attrs)

	// Timestamp events
	start, emit := msg.MetaCapabilityTimestampStart, msg.MetaCapabilityTimestampEmit
	m.writeError.capTimestampStart.Record(ctx, int64(start), attrs)
	m.writeError.capTimestampEmit.Record(ctx, int64(emit), attrs)
	m.writeError.capDuration.Record(ctx, int64(emit-start), attrs)
	return nil
}

func (m *Metrics) OnWriteSent(ctx context.Context, msg *WriteSent, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.writeSent.count.Add(ctx, 1, attrs)

	// Timestamp events
	start, emit := msg.MetaCapabilityTimestampStart, msg.MetaCapabilityTimestampEmit
	m.writeSent.capTimestampStart.Record(ctx, int64(start), attrs)
	m.writeSent.capTimestampEmit.Record(ctx, int64(emit), attrs)
	m.writeSent.capDuration.Record(ctx, int64(emit-start), attrs)

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

func (m *Metrics) OnWriteConfirmed(ctx context.Context, msg *WriteConfirmed, attrKVs ...any) error {
	// Define attributes
	attrs := metric.WithAttributes(msg.Attributes()...)

	// Count events
	m.writeConfirmed.count.Add(ctx, 1, attrs)

	// Timestamp events
	start, emit := msg.MetaCapabilityTimestampStart, msg.MetaCapabilityTimestampEmit
	m.writeConfirmed.capTimestampStart.Record(ctx, int64(start), attrs)
	m.writeConfirmed.capTimestampEmit.Record(ctx, int64(emit), attrs)
	m.writeConfirmed.capDuration.Record(ctx, int64(emit-start), attrs)

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

// Attributes returns the attributes for the WriteInitiated message to be used in metrics
func (m *WriteInitiated) Attributes() []attribute.KeyValue {
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
		attribute.String("node", m.Node),
		attribute.String("forwarder", m.Forwarder),
		attribute.String("receiver", m.Receiver),
		attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
	}

	return append(attrs, context.Attributes()...)
}

// Attributes returns the attributes for the WriteError message to be used in metrics
func (m *WriteError) Attributes() []attribute.KeyValue {
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
		attribute.String("node", m.Node),
		attribute.String("forwarder", m.Forwarder),
		attribute.String("receiver", m.Receiver),
		attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
		// Error information
		attribute.Int64("code", int64(m.Code)), // uint32 -> int64
		attribute.String("summary", m.Summary),
	}

	return append(attrs, context.Attributes()...)
}

// Attributes returns the attributes for the WriteSent message to be used in metrics
func (m *WriteSent) Attributes() []attribute.KeyValue {
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
		attribute.String("node", m.Node),
		attribute.String("forwarder", m.Forwarder),
		attribute.String("receiver", m.Receiver),
		attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
	}

	return append(attrs, context.Attributes()...)
}

// Attributes returns the attributes for the WriteConfirmed message to be used in metrics
func (m *WriteConfirmed) Attributes() []attribute.KeyValue {
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
		attribute.String("node", m.Node),
		attribute.String("forwarder", m.Forwarder),
		attribute.String("receiver", m.Receiver),
		attribute.Int64("report_id", int64(m.ReportId)), // uint32 -> int64
		attribute.String("transmitter", m.Transmitter),
		attribute.Bool("success", m.Success),
	}

	return append(attrs, context.Attributes()...)
}
