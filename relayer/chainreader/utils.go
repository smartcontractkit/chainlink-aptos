package chainreader

import (
	"fmt"
	"strconv"

	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
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

func compareValue(fieldValue, compareValue any, operator primitives.ComparisonOperator) bool {
	// If the field value is a string and the comparator is numeric, try to parse it.
	if fieldStr, ok := fieldValue.(string); ok {
		if cmpNum, ok := compareValue.(uint64); ok {
			num, err := strconv.ParseUint(fieldStr, 10, 64)
			if err != nil {
				return false
			}
			var result bool
			switch operator {
			case primitives.Eq:
				result = num == cmpNum
			case primitives.Neq:
				result = num != cmpNum
			case primitives.Gt:
				result = num > cmpNum
			case primitives.Lt:
				result = num < cmpNum
			case primitives.Gte:
				result = num >= cmpNum
			case primitives.Lte:
				result = num <= cmpNum
			default:
				return false
			}
			return result
		}

		// Fallback: if both values are strings, do string comparison.
		if compareStr, ok := compareValue.(string); ok {
			switch operator {
			case primitives.Eq:
				return fieldStr == compareStr
			case primitives.Neq:
				return fieldStr != compareStr
			default:
				return false
			}
		}
		return false
	}

	// Fallback: try decoding the field value to a uint64.
	var fieldNum uint64
	if err := codec.DecodeAptosJsonValue(fieldValue, &fieldNum); err != nil {
		return false
	}

	cmpNum, ok := compareValue.(uint64)
	if !ok {
		return false
	}

	var result bool
	switch operator {
	case primitives.Eq:
		result = fieldNum == cmpNum
	case primitives.Neq:
		result = fieldNum != cmpNum
	case primitives.Gt:
		result = fieldNum > cmpNum
	case primitives.Lt:
		result = fieldNum < cmpNum
	case primitives.Gte:
		result = fieldNum >= cmpNum
	case primitives.Lte:
		result = fieldNum <= cmpNum
	default:
		result = false
	}

	return result
}

func isNumeric(value any) bool {
	_, ok := value.(uint64)
	return ok
}
