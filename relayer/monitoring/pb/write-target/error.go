package write_target

import (
	"context"
	"fmt"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

// AsError returns the WriteError message as an (Go) error
func (e *WriteError) AsError() error {
	protoName := protoimpl.X.MessageTypeOf(e).Descriptor().FullName()
	return fmt.Errorf("%s [ERR-%v] - %s: %s", protoName, e.Code, e.Summary, e.Cause)
}

// AsEmittedError returns the WriteError message as an (Go) error, after emitting it first
func (e *WriteError) AsEmittedError(ctx context.Context, client *monitor.BeholderClient, attrKVs ...any) error {
	// Notice: we always want to log the error
	err := client.ProtoEmitter.EmitWithLog(ctx, e, attrKVs...)
	if err != nil {
		return fmt.Errorf("failed to emit error: %+w", err)
	}
	return e.AsError()
}
