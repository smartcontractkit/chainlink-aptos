package write_target

import (
	"context"
	"fmt"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/data-feeds/on-chain/registry"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/keystone/on-chain/forwarder"
	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/keystone/write-target"
)

// TODO: this is just a PoC implementation - replace with more robust implementation
func NewAptosWriteTargetMonitor(ctx context.Context, lggr logger.Logger) (*monitor.BeholderClient, error) {
	// Initialize the Beholder client with a local logger a custom Emitter
	client := beholder.GetClient().ForPackage("write_target")

	registryMetrics, err := registry.NewMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to create new registry metrics: %w", err)
	}

	forwarderMetrics, err := forwarder.NewMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to create new forwarder metrics: %w", err)
	}

	wtMetrics, err := wt.NewMetrics()
	if err != nil {
		return nil, fmt.Errorf("failed to create new write target metrics: %w", err)
	}

	protoEmitterProxy := protoEmitter{
		emitter: monitor.NewProtoEmitter(lggr, &client),
		// Metrics collection
		metrics: struct {
			registry  *registry.Metrics
			forwarder *forwarder.Metrics
			wt        *wt.Metrics
		}{
			registry:  registryMetrics,
			forwarder: forwarderMetrics,
			wt:        wtMetrics,
		},
	}
	return &monitor.BeholderClient{&client, &protoEmitterProxy}, nil
}

// Specific to the Aptos WT
type protoEmitter struct {
	emitter monitor.ProtoEmitter
	// Metrics collection
	metrics struct {
		registry  *registry.Metrics
		forwarder *forwarder.Metrics
		wt        *wt.Metrics
	}
}

func (e *protoEmitter) Emit(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// TODO: implement me
	return nil
}

// TODO: the way this is currently used, these errors will be swallowed
func (e *protoEmitter) EmitWithLog(ctx context.Context, m proto.Message, attrKVs ...any) error {
	err := e.emitter.EmitWithLog(ctx, m, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit with log: %w", err)
	}

	// Switch on the type of the proto.Message
	switch msg := m.(type) {
	case *wt.WriteInitiated:
		err = e.metrics.wt.OnWriteInitiated(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to publish write initiated metrics: %w", err)
		}
		return nil
	case *wt.WriteError:
		err = e.metrics.wt.OnWriteError(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to publish write error metrics: %w", err)
		}
		return nil
	case *wt.WriteSent:
		err = e.metrics.wt.OnWriteSent(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to publish write sent metrics: %w", err)
		}
		return nil
	case *wt.WriteConfirmed:
		err = e.metrics.wt.OnWriteConfirmed(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to publish write confirmed metrics: %w", err)
		}

		// Further processing for 'WriteConfirmed' messages
		return e.decodeAndProcessWriteConfirmed(ctx, msg, attrKVs...)
	default:
		// Not a recognized message type
		return fmt.Errorf("unrecognized message type: %T", m)
	}
}

func (e *protoEmitter) decodeAndProcessWriteConfirmed(ctx context.Context, m *wt.WriteConfirmed, attrKVs ...any) error {
	// Decode as a 'keystone.forwarder.ReportProcessed' message
	reportProcessed, err := forwarder.DecodeAsReportProcessed(m)
	if err != nil {
		return fmt.Errorf("failed to decode as 'keystone.forwarder.ReportProcessed': %w", err)
	}
	// Emit the 'keystone.forwarder.ReportProcessed' message
	err = e.emitter.EmitWithLog(ctx, reportProcessed, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit with log: %w", err)
	}
	// Process emit and derive metrics
	err = e.metrics.forwarder.OnReportProcessed(ctx, reportProcessed)
	if err != nil {
		return fmt.Errorf("failed to publish report processed metrics: %w", err)
	}

	// TODO: add option for other products

	// Decode as an array of 'data-feeds.registry.FeedUpdated' messages
	updates, err := registry.DecodeAsFeedUpdated(m)
	if err != nil {
		return fmt.Errorf("failed to decode as 'data-feeds.registry.FeedUpdated': %w", err)
	}
	// Emit the 'data-feeds.registry.FeedUpdated' messages
	for _, update := range updates {
		err = e.emitter.EmitWithLog(ctx, update, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to emit with log: %w", err)
		}
		// Process emit and derive metrics
		err = e.metrics.registry.OnFeedUpdated(ctx, update)
		if err != nil {
			return fmt.Errorf("failed to publish feed updated metrics: %w", err)
		}
	}

	return nil
}
