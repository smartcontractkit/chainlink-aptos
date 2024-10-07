package write_target

import (
	"context"
	"fmt"
	"google.golang.org/protobuf/proto"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/on-chain/data-feeds/registry"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/on-chain/keystone/forwarder"
	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

func NewAptosWriteTargetMonitor(ctx context.Context, lggr logger.Logger) *monitor.BeholderClient {
	// Initialize the Beholder client with a local logger a custom Emitter
	client := beholder.GetClient().ForPackage("write_target")
	protoEmitter := protoEmitter{
		emitter: monitor.NewProtoEmitter(lggr, &client),
	}
	return &monitor.BeholderClient{&client, &protoEmitter}
}

// TODO: this is just a PoC implementation
// Specific to the Aptos WT
type protoEmitter struct {
	emitter monitor.ProtoEmitter
}

func (e *protoEmitter) Emit(ctx context.Context, m proto.Message, attrKVs ...any) error {
	// TODO: implement me
	return nil
}

func (e *protoEmitter) EmitWithLog(ctx context.Context, m proto.Message, attrKVs ...any) error {
	err := e.emitter.EmitWithLog(ctx, m, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit with log: %w", err)
	}

	// Try to cast as 'write_target.WriteConfirmed'
	writeConfirmed, ok := m.(*wt.WriteConfirmed)
	if !ok {
		// Not a 'write_target.WriteConfirmed' message
		return nil
	}

	// Decode as a 'keystone.forwarder.ReportProcessed' message
	reportProcessed, err := forwarder.DecodeAsReportProcessed(writeConfirmed)
	if err != nil {
		return fmt.Errorf("failed to decode as 'keystone.forwarder.ReportProcessed': %w", err)
	}
	// Emit the 'keystone.forwarder.ReportProcessed' message
	err = e.emitter.EmitWithLog(ctx, reportProcessed, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit with log: %w", err)
	}

	// Decode as an array of 'data-feeds.registry.FeedUpdated' messages
	updates, err := registry.DecodeAsFeedUpdated(writeConfirmed)
	if err != nil {
		return fmt.Errorf("failed to decode as 'data-feeds.registry.FeedUpdated': %w", err)
	}
	// Emit the 'data-feeds.registry.FeedUpdated' messages
	for _, update := range updates {
		err = e.emitter.EmitWithLog(ctx, update, attrKVs...)
		if err != nil {
			return fmt.Errorf("failed to emit with log: %w", err)
		}
	}

	return nil
}
