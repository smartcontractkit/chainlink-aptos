package monitor

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type BeholderClient struct {
	*beholder.Client
	ProtoEmitter ProtoEmitter
}

// ProtoEmitter is an interface for emitting protobuf messages
// TODO: this should be moved to chainlink-common
type ProtoEmitter interface {
	// Sends message with bytes and attributes to OTel Collector
	Emit(ctx context.Context, m proto.Message, attrKVs ...any) error
	EmitWithLog(ctx context.Context, m proto.Message, attrKVs ...any) error
}

func NewProtoEmitter(lggr logger.Logger, client *beholder.Client) ProtoEmitter {
	return &protoEmitter{lggr, client}
}

type protoEmitter struct {
	lggr   logger.Logger
	client *beholder.Client
}

func (e *protoEmitter) Emit(ctx context.Context, m proto.Message, attrKVs ...any) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		// Notice: we log here because emit errors are usually not critical and swallowed by the caller
		e.lggr.Errorw("[Beholder] Failed to marshal", "err", err)
		return err
	}

	// Add the message type as an attribute (required)
	protoName := protoimpl.X.MessageTypeOf(m).Descriptor().FullName()
	attrKVs = append(attrKVs, "beholder_data_schema")
	// TODO: needs to be an URI (Beholder requirement)
	// Notice: work on Beholder schema registry is in progress, for now we use a simple / prefix to indicate an URI
	attrKVs = append(attrKVs, fmt.Sprintf("/%s/versions/1", string(protoName)))

	// Emit the message with attributes
	err = e.client.Emitter.Emit(ctx, payload, attrKVs...)
	if err != nil {
		// Notice: we log here because emit errors are usually not critical and swallowed by the caller
		e.lggr.Errorw("[Beholder] Failed to client.Emitter.Emit", "err", err)
		return err
	}

	return nil
}

// EmitWithLog emits a protobuf message with attributes and logs the emitted message
func (e *protoEmitter) EmitWithLog(ctx context.Context, m proto.Message, attrKVs ...any) error {
	err := e.Emit(ctx, m, attrKVs...)
	if err != nil {
		return err
	}

	protoName := protoimpl.X.MessageTypeOf(m).Descriptor().FullName()
	protoStr := protoimpl.X.MessageStringOf(m)
	// TODO: log attributes as well
	e.lggr.Infow("[Beholder.emit]", "name", protoName, "message", protoStr)

	return nil
}

type BeholderClientOpts struct {
	Logger logger.Logger
	Config beholder.Config
}

func NewBeholderClient(ctx context.Context, opts BeholderClientOpts) (*beholder.Client, error) {
	opts.Logger.Debugw("[Beholder] creating client", "config", opts.Config)

	// Initialize beholder otel client which sets up OTel components
	otelClient, err := beholder.NewClient(ctx, opts.Config)
	if err != nil {
		return &beholder.Client{}, fmt.Errorf("failed to create a new Beholder client: %+w", err)
	}
	// Handle OTel errors
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		opts.Logger.Errorw("[Beholder] OTEL error", "err", err)
	}))
	// Set global client so it will be accessible from anywhere through beholder/global functions
	beholder.SetClient(otelClient)

	return otelClient, nil
}

// This is for development purposes only, should not be used in production
// Beholder configuration should be sourced from core node toml configuration
func BeholderDevConfig() beholder.Config {
	config := beholder.DefaultConfig()
	// Set the OTel exporter endpoint
	config.OtelExporterGRPCEndpoint = "otelcollector:4317"
	// Add some more Resource Attributes
	// Resource Attributes are static and are added to each emitted OTel data type
	config.ResourceAttributes = append(config.ResourceAttributes, []attribute.KeyValue{
		attribute.String("chain_id", "11155111"),
		attribute.String("node_id", "dev-node-id"),
	}...)
	// Emitter
	// Disable batching, should not be used in production
	config.EmitterBatchProcessor = false
	// Trace
	config.TraceSampleRatio = 1
	config.TraceBatchTimeout = 1 * time.Second
	// Metric
	config.MetricReaderInterval = 1 * time.Second
	// Log
	config.LogExportTimeout = 1 * time.Second
	// Disable batching, should not be used in production
	config.LogBatchProcessor = false
	return config
}
