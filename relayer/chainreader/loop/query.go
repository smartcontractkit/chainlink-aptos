package loop

import (
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"

	"github.com/smartcontractkit/chainlink-aptos/codec/loop"
)

// Deprecated: use loop.SerializeExpressions
func SerializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	return loop.SerializeExpressions(exprs)
}

// Deprecated: use loop.DeserializeExpressions
func DeserializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	return loop.DeserializeExpressions(exprs)
}
