package write_target

import (
	"fmt"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
)

// AsError returns the WriteError message as an (Go) error
func (err *WriteError) AsError() error {
	return fmt.Errorf("[ERR-%v] %s: %s", err.Code, err.Summary, err.Cause)
}

// AsEmittedError returns the WriteError message as an (Go) error, after emitting it first
func (err *WriteError) AsEmittedError(beholder *monitor.BeholderClient) error {
	_err := beholder.Emit(err)
	if _err != nil {
		return fmt.Errorf("failed to emit via beholder: %+w", _err)
	}
	return err.AsError()
}
