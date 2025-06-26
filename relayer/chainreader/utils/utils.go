package utils

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

func UnwrapSlice(value any) ([]any, bool) {
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

func ExtractTimestampFilter(expressions []query.Expression) (uint64, bool) {
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

func MaybeRenameFields(jsonValue any, renames map[string]config.RenamedField) error {
	// no renames are provided, we don't put any constraint on jsonValue
	if len(renames) == 0 {
		return nil
	}

	if jsonMap, ok := jsonValue.(map[string]any); ok {
		if err := RenameMapFields(jsonMap, renames); err != nil {
			return err
		}
	} else if jsonSlice, ok := UnwrapSlice(jsonValue); ok {
		for i, elem := range jsonSlice {
			if elemMap, ok := elem.(map[string]any); ok {
				if err := RenameMapFields(elemMap, renames); err != nil {
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

func RenameMapFields(jsonData map[string]any, renames map[string]config.RenamedField) error {
	for origName, rename := range renames {
		subValue, ok := jsonData[origName]
		if !ok {
			return fmt.Errorf("no such field: %s", origName)
		}

		// it's possible we don't want to rename this field, but only want the sub fields to be renamed.
		if rename.NewName != "" && rename.NewName != origName {
			jsonData[rename.NewName] = subValue
			delete(jsonData, origName)
		}

		if err := MaybeRenameFields(subValue, rename.SubFieldRenames); err != nil {
			return fmt.Errorf("sub field renames failed for field %s: %+w", origName, err)
		}
	}
	return nil
}

func ApplyEventFilterRenames(exprs []query.Expression, renames map[string]string) []query.Expression {
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
			// Apply renames recursively to nested expressions
			boolExpr := expr.BoolExpression
			nestedExprs := ApplyEventFilterRenames(boolExpr.Expressions, renames)
			newExprs[i] = query.Expression{
				BoolExpression: query.BoolExpression{
					Expressions:  nestedExprs,
					BoolOperator: boolExpr.BoolOperator,
				},
			}
		}
	}
	return newExprs
}

// Regex for validating the JSON path - allows dot-separated sequences of alphabetic characters and underscores
var validJsonPathPattern = regexp.MustCompile(`^[a-zA-Z_]+(\.[a-zA-Z_]+)*$`)

// buildJsonPathExpr constructs a PostgreSQL JSON path expression for accessing nested fields
// Example: "Header.SourceChainSelector" becomes data->'Header'->>'SourceChainSelector'
func BuildJsonPathExpr(baseField string, path string) (string, error) {
	if !validJsonPathPattern.MatchString(path) {
		return "", fmt.Errorf("invalid json path: %s (must contain only letters separated by dots)", path)
	}

	parts := strings.Split(path, ".")
	expr := baseField

	for i, part := range parts {
		if i == len(parts)-1 {
			expr = fmt.Sprintf("%s->>'%s'", expr, part)
		} else {
			expr = fmt.Sprintf("%s->'%s'", expr, part)
		}
	}

	return expr, nil
}

func IsNumeric(value any) bool {
	_, ok := value.(uint64)
	return ok
}

func ExtractEventCreationNum(resourceData map[string]any, eventFieldPath string) (string, error) {
	pathComponents := strings.Split(eventFieldPath, ".")

	current, ok := resourceData["data"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("resource data missing 'data' field or not a map")
	}

	for i, component := range pathComponents {
		nextLevel, ok := current[component].(map[string]any)
		if !ok {
			return "", fmt.Errorf("cannot navigate path at component %s (position %d): field missing or not a map",
				component, i)
		}
		current = nextLevel
	}

	guid, ok := current["guid"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("event field missing 'guid' structure")
	}

	id, ok := guid["id"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("event field missing 'guid.id' structure")
	}

	creationNum, ok := id["creation_num"].(string)
	if !ok {
		return "", fmt.Errorf("event field missing 'guid.id.creation_num' value or not a string")
	}

	return creationNum, nil
}
