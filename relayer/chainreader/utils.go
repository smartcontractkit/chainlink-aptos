package chainreader

import (
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

func unwrapSlice(value any) ([]any, bool) {
	sliceValue, ok := value.([]any)
	if !ok {
		return nil, false
	}
	for len(sliceValue) == 1 {
		innerSliceValue, ok := sliceValue[0].([]any)
		if !ok {
			break
		}
		sliceValue = innerSliceValue
	}
	return sliceValue, true
}

func extractTimestampFilter(expressions []query.Expression) (uint64, bool) {
	for _, expr := range expressions {
		if expr.IsPrimitive() {
			if tsExpr, ok := expr.Primitive.(*primitives.Timestamp); ok {
				if tsExpr.Operator == primitives.Gte {
					return tsExpr.Timestamp, true
				}
			}
		}
	}
	return 0, false
}

func maybeRenameFields(jsonValue any, renames map[string]RenamedField) error {
	// no renames are provided, we don't put any constraint on jsonValue
	if len(renames) == 0 {
		return nil
	}

	if jsonMap, ok := jsonValue.(map[string]any); ok {
		if err := renameMapFields(jsonMap, renames); err != nil {
			return err
		}
	} else if jsonSlice, ok := unwrapSlice(jsonValue); ok {
		for i, elem := range jsonSlice {
			if elemMap, ok := elem.(map[string]any); ok {
				if err := renameMapFields(elemMap, renames); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("sub field renames provided but array element at index %d is not a map: %T", i, elem)
			}
		}
	} else {
		return fmt.Errorf("sub field renames provided but value is not a map or slice of maps: %T", jsonValue)
	}

	return nil
}

func renameMapFields(jsonData map[string]any, renames map[string]RenamedField) error {
	for origName, rename := range renames {
		subValue, ok := jsonData[origName]
		if !ok {
			return fmt.Errorf("no such field: %s", origName)
		}

		// it's possible we don't want to rename this field, but only want the sub fields to be renamed.
		if rename.NewName != "" {
			jsonData[rename.NewName] = subValue
			delete(jsonData, origName)
		}

		if err := maybeRenameFields(subValue, rename.SubFieldRenames); err != nil {
			return fmt.Errorf("sub field renames failed for field %s: %+w", origName, err)
		}
	}
	return nil
}

func applyEventFilterRenames(exprs []query.Expression, renames map[string]string) []query.Expression {
	newExprs := make([]query.Expression, len(exprs))
	for i, expr := range exprs {
		if expr.IsPrimitive() {
			if comp, ok := expr.Primitive.(*primitives.Comparator); ok {
				newName := comp.Name
				if renamed, exists := renames[comp.Name]; exists {
					newName = renamed
				}
				newExprs[i] = query.Comparator(newName, comp.ValueComparators...)
			} else {
				newExprs[i] = expr
			}
		} else {
			newExprs[i] = expr
		}
	}
	return newExprs
}

// buildJsonPathExpr constructs a PostgreSQL JSON path expression for accessing nested fields
// Example: "Header.SourceChainSelector" becomes data->'Header'->>'SourceChainSelector'
func buildJsonPathExpr(baseField string, path string) string {
	parts := strings.Split(path, ".")
	expr := baseField

	for i, part := range parts {
		if i == len(parts)-1 {
			expr = fmt.Sprintf("%s->>'%s'", expr, part)
		} else {
			expr = fmt.Sprintf("%s->'%s'", expr, part)
		}
	}

	return expr
}

func isNumeric(value any) bool {
	_, ok := value.(uint64)
	return ok
}
