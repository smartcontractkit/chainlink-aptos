package loop

import (
	"encoding/json"
	"fmt"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

const MAX_EXPRESSION_DEPTH = 32

func SerializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	serializedExprs := make([]query.Expression, 0, len(exprs))
	for _, expr := range exprs {
		serializedExpr, err := serializeExpressionValues(expr, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize expression: %w", err)
		}
		serializedExprs = append(serializedExprs, serializedExpr)
	}
	return serializedExprs, nil
}

func DeserializeExpressions(exprs []query.Expression) ([]query.Expression, error) {
	deserializedExprs := make([]query.Expression, 0, len(exprs))
	for _, expr := range exprs {
		deserializedExpr, err := deserializeExpressionValues(expr, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize expression: %w", err)
		}
		deserializedExprs = append(deserializedExprs, deserializedExpr)
	}
	return deserializedExprs, nil
}

// the relay wrapper calls getContractEncodedType which defaults to returning a map[string]any
// https://github.com/smartcontractkit/chainlink-common/blob/fe3ec4466fb5adfffd8fc77eef1cef67c4a918cc/pkg/loop/internal/relayer/pluginprovider/contractreader/contract_reader.go#L1033
// in ccipChainReader.ExecutedMessages, it's a primitive

func serializeExpressionValues(expr query.Expression, depth int) (query.Expression, error) {
	if depth > MAX_EXPRESSION_DEPTH {
		return expr, fmt.Errorf("expression depth exceeds maximum allowed depth of %d", MAX_EXPRESSION_DEPTH)
	}

	resultExpr := expr
	var err error

	if expr.Primitive != nil {
		if comp, ok := expr.Primitive.(*primitives.Comparator); ok {
			if comp == nil {
				return expr, fmt.Errorf("invalid Expression: Primitive is *primitives.Comparator but pointer is nil")
			}
			newComp := &primitives.Comparator{
				Name:             comp.Name,
				ValueComparators: make([]primitives.ValueComparator, len(comp.ValueComparators)),
			}
			for i, vc := range comp.ValueComparators {
				var jsonData []byte
				jsonData, err = json.Marshal(vc.Value)
				if err != nil {
					return expr, fmt.Errorf("failed to marshal value in comparator '%s' (type %T): %w", comp.Name, vc.Value, err)
				}
				newComp.ValueComparators[i] = primitives.ValueComparator{
					Value:    &jsonData,
					Operator: vc.Operator,
				}
			}
			resultExpr.Primitive = newComp
		}
	}

	if !isZeroBoolExpression(expr.BoolExpression) {
		originalBoolExpr := expr.BoolExpression
		processedSubExprs := make([]query.Expression, 0, len(originalBoolExpr.Expressions))

		for _, subExpr := range originalBoolExpr.Expressions {
			var processedSubExpr query.Expression
			processedSubExpr, err = serializeExpressionValues(subExpr, depth+1)
			if err != nil {
				return expr, fmt.Errorf("failed processing sub-expression within %s: %w", originalBoolExpr.BoolOperator, err)
			}
			processedSubExprs = append(processedSubExprs, processedSubExpr)
		}
		resultExpr.BoolExpression = query.BoolExpression{
			Expressions:  processedSubExprs,
			BoolOperator: originalBoolExpr.BoolOperator,
		}
	}

	return resultExpr, nil
}

func deserializeExpressionValues(expr query.Expression, depth int) (query.Expression, error) {
	if depth > MAX_EXPRESSION_DEPTH {
		return expr, fmt.Errorf("expression depth exceeds maximum allowed depth of %d", MAX_EXPRESSION_DEPTH)
	}

	resultExpr := expr
	var err error

	if expr.Primitive != nil {
		if comp, ok := expr.Primitive.(*primitives.Comparator); ok {
			if comp == nil {
				return expr, fmt.Errorf("invalid Expression: Primitive is *primitives.Comparator but pointer is nil")
			}
			newComp := &primitives.Comparator{
				Name:             comp.Name,
				ValueComparators: make([]primitives.ValueComparator, len(comp.ValueComparators)),
			}
			for i, vc := range comp.ValueComparators {
				if vc.Value == nil {
					newComp.ValueComparators[i] = primitives.ValueComparator{
						Value:    nil,
						Operator: vc.Operator,
					}
					continue
				}

				jsonData, ok := vc.Value.(*[]byte)
				if !ok {
					return expr, fmt.Errorf("failed to deserialize value in comparator '%s': expected []byte, got %T", comp.Name, vc.Value)
				}

				var target uint64
				err = json.Unmarshal(*jsonData, &target)
				if err != nil {
					return expr, fmt.Errorf("failed to unmarshal value '%s' in comparator '%s': %w", string(*jsonData), comp.Name, err)
				}
				newComp.ValueComparators[i] = primitives.ValueComparator{
					Value:    target,
					Operator: vc.Operator,
				}
			}
			resultExpr.Primitive = newComp
		}
	}

	if !isZeroBoolExpression(expr.BoolExpression) {
		originalBoolExpr := expr.BoolExpression
		processedSubExprs := make([]query.Expression, 0, len(originalBoolExpr.Expressions))

		for _, subExpr := range originalBoolExpr.Expressions {
			var processedSubExpr query.Expression
			processedSubExpr, err = deserializeExpressionValues(subExpr, depth+1)
			if err != nil {
				return expr, fmt.Errorf("failed processing sub-expression within %s: %w", originalBoolExpr.BoolOperator, err)
			}
			processedSubExprs = append(processedSubExprs, processedSubExpr)
		}
		resultExpr.BoolExpression = query.BoolExpression{
			Expressions:  processedSubExprs,
			BoolOperator: originalBoolExpr.BoolOperator,
		}
	}

	return resultExpr, nil
}

func isZeroBoolExpression(be query.BoolExpression) bool {
	return len(be.Expressions) == 0
}
