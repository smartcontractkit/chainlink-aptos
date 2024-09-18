package monitor

import (
	"context"
	"fmt"

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

// Add the message type as an attribute (required)
func appendSchemaIfMissing(m proto.Message, attrKVs []any) []any {
	key := "beholder_data_schema"
	hasSchema := false
	for i := 0; i < len(attrKVs); i += 2 {
		if attrKVs[i] == key {
			hasSchema = true
			break
		}
	}

	if !hasSchema {
		protoName := protoimpl.X.MessageTypeOf(m).Descriptor().FullName()
		attrKVs = append(attrKVs, key)
		// TODO: needs to be an URI (Beholder requirement)
		// Notice: work on Beholder schema registry is in progress, for now we use a simple / prefix to indicate an URI
		attrKVs = append(attrKVs, fmt.Sprintf("/%s/versions/1", string(protoName)))
	}

	return attrKVs
}

func (e *protoEmitter) Emit(ctx context.Context, m proto.Message, attrKVs ...any) error {
	payload, err := proto.Marshal(m)
	if err != nil {
		// Notice: we log here because emit errors are usually not critical and swallowed by the caller
		e.lggr.Errorw("[Beholder] Failed to marshal", "err", err)
		return err
	}

	attrKVs = appendSchemaIfMissing(m, attrKVs)

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
	attrKVs = appendSchemaIfMissing(m, attrKVs)

	mStr := fmt.Sprintf("{%s}", protoimpl.X.MessageStringOf(m))
	// TODO: how do we get and log the full set of attributes?
	e.lggr.Infow("[Beholder.emit]", "message", mStr, "attributes", attrKVs)

	err := e.Emit(ctx, m, attrKVs...)

	return err
}

type BeholderClientOpts struct {
	Logger logger.Logger
	Config beholder.Config
}
