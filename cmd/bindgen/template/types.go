package template

import (
	"errors"
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-aptos/cmd/bindgen/parse"
)

func createGoTypeFromMove(s string, localStructs map[string]parse.Struct, externalStructs []parse.ExternalStruct) (tmplType, error) {
	switch s {
	case "u8":
		return tmplType{
			GoType:   "byte",
			MoveType: s,
		}, nil
	case "u16":
		return tmplType{
			GoType:   "uint16",
			MoveType: s,
		}, nil
	case "u32":
		return tmplType{
			GoType:   "uint32",
			MoveType: s,
		}, nil
	case "u64":
		return tmplType{
			GoType:   "uint64",
			MoveType: s,
		}, nil
	case "u128", "u256":
		return tmplType{
			GoType:   "*big.Int",
			MoveType: s,
		}, nil
	case "bool":
		return tmplType{
			GoType:   "bool",
			MoveType: s,
		}, nil
	case "address":
		return tmplType{
			GoType:   "aptos.AccountAddress",
			MoveType: s,
		}, nil
	case "String", "string::String", "std::string::String":
		return tmplType{
			GoType:   "string",
			MoveType: "0x1::string::String",
		}, nil
	default:
		// Vectors
		if innerTypeName, _, ok := isGenericType(s, "vector"); ok {
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs, externalStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   fmt.Sprintf("[]%s", innerType.GoType),
				MoveType: fmt.Sprintf("vector<%s>", innerType.MoveType),
			}, nil
		}

		// Check if local struct
		if _, ok := localStructs[s]; ok {
			return tmplType{
				GoType:   s,
				MoveType: s,
			}, nil
		}

		// Check if external struct
		for _, externalStruct := range externalStructs {
			// Type could be used as package::module::Struct, module::Struct or Struct directly, depending on the import
			if s == fmt.Sprintf("%s::%s::%s", externalStruct.Package, externalStruct.Module, externalStruct.Name) ||
				s == fmt.Sprintf("%s::%s", externalStruct.Module, externalStruct.Name) ||
				s == externalStruct.Name {
				return tmplType{
					GoType:   fmt.Sprintf("module_%s.%s", externalStruct.Module, ToUpperCamelCase(externalStruct.Name)),
					MoveType: s,
					Import: &tmplImport{
						Path:        externalStruct.ImportPath,
						PackageName: fmt.Sprintf("module_%s", externalStruct.Module),
					},
				}, nil
			}
		}

		// Hardcoded stdlib structs
		if innerTypeName, _, ok := isGenericType(s, "std::option::Option"); ok {
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs, externalStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   "*" + innerType.GoType,
				MoveType: fmt.Sprintf("0x1::option::Option<%s>", innerType.MoveType),
				StdOption: &tmplOption{
					UnderlyingGoType: innerType.GoType,
				},
			}, nil
		}
		if _, _, ok := isGenericType(s, "aptos_framework::object::Object"); ok {
			return tmplType{
				GoType:          "aptos.AccountAddress",
				GoInternalType:  "bind.StdObject",
				MoveType:        "address",
				MoveInteralType: "aptos_framework::object::Object",
				StdObject:       true,
			}, nil
		}
		if innerTypeName, _, ok := isGenericType(s, "std::simple_map::SimpleMap"); ok {
			splitInnerType := strings.Split(innerTypeName, ",")
			if len(splitInnerType) != 2 {
				return tmplType{}, errors.New("invalid type parameters in std::simple_map::SimpleMap")
			}
			keyName := strings.TrimSpace(splitInnerType[0])
			valueName := strings.TrimSpace(splitInnerType[1])
			keyType, err := createGoTypeFromMove(keyName, localStructs, externalStructs)
			if err != nil {
				return tmplType{}, fmt.Errorf("invalid key type parameter %q in std::simple_map::SimpleMap: %w", keyName, err)
			}
			valueType, err := createGoTypeFromMove(valueName, localStructs, externalStructs)
			if err != nil {
				return tmplType{}, fmt.Errorf("invalid value type parameter %q in std::simple_map::SimpleMap: %w", valueName, err)
			}

			return tmplType{
				GoType:   fmt.Sprintf("*bind.StdSimpleMap[%s,%s]", keyType.GoType, valueType.GoType),
				MoveType: fmt.Sprintf("std::simple_map::SimpleMap<%s,%s>", keyName, valueName),
			}, nil
		}
	}
	return tmplType{}, fmt.Errorf("unknown move type: %s", s)
}

func isGenericType(s string, typ string) (innerType string, moveType string, ok bool) {
	// package::module::Struct
	split := strings.SplitN(typ, "::", 3)

	if !strings.HasSuffix(s, ">") {
		return "", "", false
	}
	s = strings.TrimSuffix(s, ">")

	if strings.HasPrefix(s, fmt.Sprintf("%s<", split[len(split)-1])) {
		innerType = strings.TrimPrefix(s, fmt.Sprintf("%s<", split[len(split)-1]))
		moveType = fmt.Sprintf("%s<%s>", typ, innerType)
		return innerType, moveType, true
	}
	if len(split) > 1 && strings.HasPrefix(s, fmt.Sprintf("%s::%s<", split[len(split)-2], split[len(split)-1])) {
		innerType = strings.TrimPrefix(s, fmt.Sprintf("%s::%s<", split[len(split)-2], split[len(split)-1]))
		moveType = fmt.Sprintf("%s<%s>", typ, innerType)
		return innerType, moveType, true
	}
	if len(split) > 2 && strings.HasPrefix(s, fmt.Sprintf("%s::%s::%s<", split[len(split)-3], split[len(split)-2], split[len(split)-1])) {
		innerType = strings.TrimPrefix(s, fmt.Sprintf("%s::%s::%s<", split[len(split)-3], split[len(split)-2], split[len(split)-1]))
		moveType = fmt.Sprintf("%s<%s>", typ, innerType)
		return innerType, moveType, true
	}

	return "", "", false
}

// IsGoConstant returns true if the type can be expressed as a Go constant/is immutable.
func (t tmplType) IsGoConstant() bool {
	switch t.GoType {
	case "byte", "uint8", "uint16", "uint32", "uint64", "bool":
		return true
	default:
		return false
	}
}
