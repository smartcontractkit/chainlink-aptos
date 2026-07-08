package loop

import (
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-aptos/codec/loop"
)

// NewLoopChainReader creates a ContractReader that wraps an existing ContractReader
// to work across LOOP boundaries.
//
// The wrapper provides:
// - Contract name to module address mapping
// - JSON serialization/deserialization for LOOP communication
// - Automatic contract re-binding for LOOP plugin restarts
//
// Both `logger` and `cr` parameters must be non-nil.
//
// Deprecated: use loop.NewLoopChainReader
//
//go:fix inline
func NewLoopChainReader(logger logger.Logger, cr types.ContractReader) types.ContractReader {
	return loop.NewLoopChainReader(logger, cr)
}
