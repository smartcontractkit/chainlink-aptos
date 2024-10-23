package monitor

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/runtime/protoimpl"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const schemaBasePath = "https://github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb"

// BeholderClient is a Beholder client extension with a custom ProtoEmitter
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

// ProtoProcessor is an interface for processing emitted protobuf messages
type ProtoProcessor interface {
	Process(ctx context.Context, m proto.Message, attrKVs ...any) error
}

func NewProtoEmitter(lggr logger.Logger, client *beholder.Client) ProtoEmitter {
	return &protoEmitter{lggr, client}
}

// protoEmitter is a ProtoEmitter implementation
var _ ProtoEmitter = (*protoEmitter)(nil)

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

	attrKVs, err = appendSchemaIfMissing(m, attrKVs, schemaBasePath)
	if err != nil {
		e.lggr.Errorw("[Beholder] Failed to append schema, emitting with unknown schema...", "err", err)
		attrKVs = appendSchemaUnknown(attrKVs, schemaBasePath)
	}

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
	attrKVs, err := appendSchemaIfMissing(m, attrKVs, schemaBasePath)
	if err != nil {
		e.lggr.Errorw("[Beholder] Failed to append schema, emitting with unknown schema...", "err", err)
		attrKVs = appendSchemaUnknown(attrKVs, schemaBasePath)
	}

	mStr := fmt.Sprintf("{%s}", protoimpl.X.MessageStringOf(m))
	e.lggr.Infow("[Beholder.emit]", "message", mStr, "attributes", attrKVs)

	err = e.Emit(ctx, m, attrKVs...)

	return err
}
