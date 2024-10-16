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

	// Underlying ProtoEmitter
	emitter := monitor.NewProtoEmitter(lggr, &client)

	// Proxy ProtoEmitter with additional processing
	protoEmitterProxy := protoEmitter{
		emitter: emitter,
		processors: []monitor.ProtoProcessor{
			&wtProcessor{wtMetrics},
			&keystoneProcessor{emitter, forwarderMetrics},
			&dataFeedsProcessor{emitter, registryMetrics},
		},
	}
	return &monitor.BeholderClient{&client, &protoEmitterProxy}, nil
}

// Specific to the Aptos WT
type protoEmitter struct {
	emitter    monitor.ProtoEmitter
	processors []monitor.ProtoProcessor
}

func (e *protoEmitter) Emit(ctx context.Context, m proto.Message, attrKVs ...any) error {
	err := e.emitter.Emit(ctx, m, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit: %w", err)
	}

	return e.Process(ctx, m, attrKVs...)
}

// TODO: the way this is currently used, these errors will be swallowed
func (e *protoEmitter) EmitWithLog(ctx context.Context, m proto.Message, attrKVs ...any) error {
	err := e.emitter.EmitWithLog(ctx, m, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit with log: %w", err)
	}

	return e.Process(ctx, m, attrKVs...)
}

// Process aggregates further processing for emitted messages
func (e *protoEmitter) Process(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// Further processing for emitted messages
	for _, p := range e.processors {
		err := p.Process(ctx, m, attrKVs...)
		if err != nil {
			// TODO: do we want to return here or continue processing?
			return fmt.Errorf("failed to process message: %w", err)
		}
	}
	return nil
}

// Write-Target specific processor decodes write messages to derive metrics
type wtProcessor struct {
	metrics *wt.Metrics
}

func (p *wtProcessor) Process(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// Switch on the type of the proto.Message
	switch msg := m.(type) {
	case *wt.WriteInitiated:
		err := p.metrics.OnWriteInitiated(ctx, msg, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to publish write initiated metrics: %w", err)
		}
		return nil
	case *wt.WriteError:
		err := p.metrics.OnWriteError(ctx, msg, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to publish write error metrics: %w", err)
		}
		return nil
	case *wt.WriteSent:
		err := p.metrics.OnWriteSent(ctx, msg, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to publish write sent metrics: %w", err)
		}
		return nil
	case *wt.WriteConfirmed:
		err := p.metrics.OnWriteConfirmed(ctx, msg, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to publish write confirmed metrics: %w", err)
		}
		return nil
	default:
		return nil // fallthrough
	}
}

// Keystone specific processor decodes writes as 'keystone.forwarder.ReportProcessed' messages + metrics
type keystoneProcessor struct {
	emitter monitor.ProtoEmitter
	metrics *forwarder.Metrics
}

func (p *keystoneProcessor) Process(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// Switch on the type of the proto.Message
	switch msg := m.(type) {
	case *wt.WriteConfirmed:
		// TODO: fallthrough if not Keystone forwarder write
		// Will this msg ever contain different types of writes? Hmm.

		// Decode as a 'keystone.forwarder.ReportProcessed' message
		reportProcessed, err := forwarder.DecodeAsReportProcessed(msg)
		if err != nil {
			return fmt.Errorf("failed to decode as 'keystone.forwarder.ReportProcessed': %w", err)
		}
		// Emit the 'keystone.forwarder.ReportProcessed' message
		err = p.emitter.EmitWithLog(ctx, reportProcessed, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to emit with log: %w", err)
		}
		// Process emit and derive metrics
		err = p.metrics.OnReportProcessed(ctx, reportProcessed, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to publish report processed metrics: %w", err)
		}
		return nil
	default:
		return nil // fallthrough
	}
}

// Data-Feeds specific processor decodes writes as 'data-feeds.registry.FeedUpdated' messages + metrics
type dataFeedsProcessor struct {
	emitter monitor.ProtoEmitter
	metrics *registry.Metrics
}

func (p *dataFeedsProcessor) Process(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// Switch on the type of the proto.Message
	switch msg := m.(type) {
	case *wt.WriteConfirmed:
		// TODO: fallthrough if not DF write
		// Will this msg ever contain different types of writes? Yes.

		// Decode as an array of 'data-feeds.registry.FeedUpdated' messages
		updates, err := registry.DecodeAsFeedUpdated(msg)
		if err != nil {
			return fmt.Errorf("failed to decode as 'data-feeds.registry.FeedUpdated': %w", err)
		}
		// Emit the 'data-feeds.registry.FeedUpdated' messages
		for _, update := range updates {
			err = p.emitter.EmitWithLog(ctx, update, attrKVs...)
			if err != nil {
				return fmt.Errorf("failed to emit with log: %w", err)
			}
			// Process emit and derive metrics
			err = p.metrics.OnFeedUpdated(ctx, update, attrKVs...)
			if err != nil {
				return fmt.Errorf("failed to publish feed updated metrics: %w", err)
			}
		}
		return nil
	default:
		return nil // fallthrough
	}
}
