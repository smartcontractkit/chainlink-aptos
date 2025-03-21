package template

import (
	"fmt"
	"strings"

	"github.com/smartcontractkit/chainlink-aptos/cmd/bindgen/parse"
)

func createGoTypeFromMove(s string, localStructs map[string]*parse.Struct) (tmplType, error) {
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
		if strings.HasPrefix(s, "vector<") && strings.HasSuffix(s, ">") {
			innerTypeName := strings.TrimSuffix(strings.TrimPrefix(s, "vector<"), ">")
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   "[]" + innerType.GoType,
				MoveType: s,
			}, nil
		}
		if strings.HasPrefix(s, "Option<") && strings.HasSuffix(s, ">") {
			innerTypeName := strings.TrimSuffix(strings.TrimPrefix(s, "Option<"), ">")
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   "*" + innerType.GoType,
				MoveType: fmt.Sprintf("0x1::option::Option<%s>", innerType.MoveType),
				Option: &tmplOption{
					UnderlyingGoType: innerType.GoType,
				},
			}, nil
		}
		if strings.HasPrefix(s, "option::Option<") && strings.HasSuffix(s, ">") {
			innerTypeName := strings.TrimSuffix(strings.TrimPrefix(s, "option::Option<"), ">")
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   "*" + innerType.GoType,
				MoveType: fmt.Sprintf("0x1::option::Option<%s>", innerType.MoveType),
				Option: &tmplOption{
					UnderlyingGoType: innerType.GoType,
				},
			}, nil
		}
		if strings.HasPrefix(s, "std::option::Option<") && strings.HasSuffix(s, ">") {
			innerTypeName := strings.TrimSuffix(strings.TrimPrefix(s, "std::option::Option<"), ">")
			innerType, err := createGoTypeFromMove(innerTypeName, localStructs)
			if err != nil {
				return tmplType{}, err
			}
			return tmplType{
				GoType:   "*" + innerType.GoType,
				MoveType: fmt.Sprintf("0x1::option::Option<%s>", innerType.MoveType),
				Option: &tmplOption{
					UnderlyingGoType: innerType.GoType,
				},
			}, nil
		}
		// Check if local struct
		if _, ok := localStructs[s]; ok {
			return tmplType{
				GoType:   s,
				MoveType: s,
			}, nil
		}
	}
	return tmplType{}, fmt.Errorf("unknown move type: %s", s)
}
