package loop

import "github.com/smartcontractkit/chainlink-common/pkg/types/query"

const MAX_EXPRESSION_DEPTH = query.MAX_EXPRESSION_DEPTH //nolint:revive // preserving name

// Deprecated: use query.SerializeExpressions
//
//go:fix inline
func SerializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	return query.SerializeExpressions(exprs)
}

// Deprecated: use query.DeserializeExpressions
//
//go:fix inline
func DeserializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	return query.DeserializeExpressions(exprs)
}
