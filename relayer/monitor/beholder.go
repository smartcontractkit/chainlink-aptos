package monitor

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/exp/rand"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/beholder/pb"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type BeholderClient struct {
	lggr logger.Logger
}

func NewBeholderClient(lggr logger.Logger) *BeholderClient {
	return &BeholderClient{lggr}
}

func (c *BeholderClient) Emit(m proto.Message) error {
	_, err := proto.Marshal(m)
	if err != nil {
		return err
	}

	protoName := protoimpl.X.MessageTypeOf(m).Descriptor().FullName()
	protoStr := protoimpl.X.MessageStringOf(m)
	c.lggr.Infow("[Beholder.emit]", "name", protoName, "message", protoStr)

	return nil
}

type beholderDemo struct {
	lggr logger.Logger
}

func StartBeholderDemo(lggr logger.Logger) {
	(&beholderDemo{logger.Named(lggr, "BeholderDemo")}).start()
}

func (d *beholderDemo) start() {
	d.setupBeholder()
	go d.sendCustomMessages()
	go d.sendMetricTraces()
}

func beholderDevConfig() beholder.Config {
	config := beholder.DefaultConfig()
	// Set the OTel exporter endpoint
	config.OtelExporterGRPCEndpoint = "localhost:4317"
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

func (d *beholderDemo) setupBeholder() {
	d.lggr.Debugw("Starting 'setupBeholder'")
	config := beholderDevConfig()

	d.lggr.Debugw("Beholder config", "config", config)

	// Initialize beholder otel client which sets up OTel components
	otelClient, err := beholder.NewClient(context.Background(), config)
	if err != nil {
		d.lggr.Errorw("Error creating Beholder client", "err", err)
	}
	// Handle OTel errors
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		d.lggr.Errorw("OTEL error", "err", err)
	}))
	// Set global client so it will be accessible from anywhere through beholder/global functions
	beholder.SetClient(otelClient)
}

func (d *beholderDemo) sendCustomMessages() {
	d.lggr.Debugw("Starting 'sendCustomMessages'")
	// Define a custom protobuf payload to emit
	payload := &pb.TestCustomMessage{
		BoolVal:   true,
		IntVal:    42,
		FloatVal:  3.14,
		StringVal: "custom message from chainlink",
	}
	payloadBytes, err := proto.Marshal(payload)
	if err != nil {
		d.lggr.Errorw("Failed to marshal protobuf", "err", err)
		return
	}

	// Emit the custom message anywhere from application logic
	for i := 0; ; i++ {
		d.lggr.Debugw("Beholder: emitting custom message", "ID", i)
		err := beholder.GetEmitter().Emit(context.Background(), payloadBytes,
			"beholder_data_schema", "/custom-message/versions/1", // required
			"beholder_data_type", "custom_message",
			"message_ind", i,
		)
		if err != nil {
			d.lggr.Errorw("Error emitting message", "err", err)
		}
		time.Sleep(1 * time.Second)
	}
}

func (d *beholderDemo) sendMetricTraces() {
	d.lggr.Debugw("Starting 'sendMetricTraces'")
	ctx := context.Background()

	// Define a new counter
	counter, err := beholder.GetMeter().Int64Counter("custom_message.count")
	if err != nil {
		d.lggr.Errorw("Failed to create new counter", "err", err)
	}

	// Define a new gauge
	gauge, err := beholder.GetMeter().Int64Gauge("custom_message.gauge")
	if err != nil {
		d.lggr.Errorw("Failed to create new gauge", "err", err)
	}

	for i := 0; ; i++ {
		d.lggr.Debugw("Beholder: sending metric, trace", "ID", i)
		// Use the counter and gauge for metrics within application logic
		counter.Add(ctx, 1)
		gauge.Record(ctx, rand.Int63n(101))

		// Create a new trace span
		_, span := beholder.GetTracer().Start(ctx, "sendMetricTraces", trace.WithAttributes(
			attribute.String("app_name", "beholderdemo"),
			attribute.Int64("trace_ind", int64(i)),
		))
		span.End()
		time.Sleep(1 * time.Second)
	}
}
