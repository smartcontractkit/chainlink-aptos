package txm

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
)

func CreateTypeTag(typeName string) (aptos.TypeTag, error) {
	switch typeName {
	case "u8":
		return aptos.TypeTag{Value: &aptos.U8Tag{}}, nil
	case "u32":
		return aptos.TypeTag{Value: &aptos.U32Tag{}}, nil
	case "u64":
		return aptos.TypeTag{Value: &aptos.U64Tag{}}, nil
	case "u128":
		return aptos.TypeTag{Value: &aptos.U128Tag{}}, nil
	case "bool":
		return aptos.TypeTag{Value: &aptos.BoolTag{}}, nil
	case "address":
		return aptos.TypeTag{Value: &aptos.AddressTag{}}, nil
	default:
		if strings.HasPrefix(typeName, "vector<") && strings.HasSuffix(typeName, ">") {
			innerTypeName := strings.TrimSuffix(strings.TrimPrefix(typeName, "vector<"), ">")
			innerTypeTag, err := CreateTypeTag(innerTypeName)
			if err != nil {
				return aptos.TypeTag{}, err
			}
			return aptos.TypeTag{
				Value: &aptos.VectorTag{
					TypeParam: innerTypeTag,
				}}, nil
		} else {
			// assume it's a struct.
			structTokens := strings.Split(typeName, "::")
			if len(structTokens) != 3 {
				return aptos.TypeTag{}, fmt.Errorf("invalid struct type: %s", typeName)
			}
			contractAddress := structTokens[0]
			parsedContractAddress := &aptos.AccountAddress{}
			err := parsedContractAddress.ParseStringRelaxed(contractAddress)
			if err != nil {
				return aptos.TypeTag{}, fmt.Errorf("failed to parse contract address: %s", contractAddress)
			}
			moduleName := structTokens[1]
			structName := structTokens[2]
			if strings.HasSuffix(structName, ">") {
				// there are generic types.
				openIndex := strings.Index(structName, "<")
				if openIndex <= 0 {
					// also includes openIndex == 0 because that means the struct name is empty
					return aptos.TypeTag{}, fmt.Errorf("invalid struct generic type: %s", typeName)
				}
				outerStructName := structName[0:openIndex]
				innerTypeParams := structName[openIndex+1 : len(structName)-1]
				innerTypeTokens := strings.Split(innerTypeParams, ",")
				structTypeTags := []aptos.TypeTag{}
				for _, token := range innerTypeTokens {
					token = strings.TrimSpace(token)
					tokenTypeTag, err := CreateTypeTag(token)
					if err != nil {
						return aptos.TypeTag{}, fmt.Errorf("invalid struct type token: %s", token)
					}
					structTypeTags = append(structTypeTags, tokenTypeTag)
				}
				return aptos.TypeTag{
					Value: &aptos.StructTag{
						Address:    *parsedContractAddress,
						Module:     moduleName,
						Name:       outerStructName,
						TypeParams: structTypeTags,
					},
				}, nil
			}
			return aptos.TypeTag{
				Value: &aptos.StructTag{
					Address: *parsedContractAddress,
					Module:  moduleName,
					Name:    structName,
				},
			}, nil
		}
	}
}

func CreateBcsValue(typeTag aptos.TypeTag, typeValue any) ([]byte, error) {
	serializer := &bcs.Serializer{}
	err := serializeArg(typeValue, typeTag, serializer)
	if err != nil {
		return nil, err
	}
	return serializer.ToBytes(), nil
}

// copied from https://github.com/coming-chat/go-aptos-sdk/blob/c2468230eadcf531e6aaadf961ea1e7c13ab0693/transaction_builder/builder_util.go#L222
// we don't use it directly because this is only called from TransactionBuilderABI.BuildTransactionPayload, which requires supplying the ABI first.
func serializeArg(argVal any, argType aptos.TypeTag, serializer *bcs.Serializer) error {
	switch argType.Value.GetType() {
	case aptos.TypeTagBool:
		if v, ok := argVal.(bool); ok {
			serializer.Bool(v)
			return nil
		}
	case aptos.TypeTagU8:
		if v, ok := argVal.(uint8); ok {
			serializer.U8(v)
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint8(v)) {
			serializer.U8(uint8(v))
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint8(v)) {
			serializer.U8(uint8(v))
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return err
			}
			serializer.U8(uint8(u))
			return nil
		}
	case aptos.TypeTagU32:
		if v, ok := argVal.(uint32); ok {
			serializer.U32(v)
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint32(v)) {
			serializer.U32(uint32(v))
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint32(v)) {
			serializer.U32(uint32(v))
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return err
			}
			serializer.U32(uint32(u))
			return nil
		}
	case aptos.TypeTagU64:
		if v, ok := argVal.(uint64); ok {
			serializer.U64(v)
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 {
			serializer.U64(uint64(v))
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 {
			serializer.U64(uint64(v))
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return err
			}
			serializer.U64(u)
			return nil
		}
	case aptos.TypeTagU128:
		if v, ok := argVal.(*big.Int); ok {
			serializer.U128(*v)
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 {
			b := big.NewInt(int64(v))
			serializer.U128(*b)
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 {
			b := big.NewInt(int64(v))
			serializer.U128(*b)
			return nil
		}
		if v, ok := argVal.(string); ok {
			if big, ok := big.NewInt(0).SetString(v, 10); ok {
				serializer.U128(*big)
				return nil
			}
		}
	case aptos.TypeTagAddress:
		if v, ok := argVal.(aptos.AccountAddress); ok {
			v.MarshalBCS(serializer)
			return nil
		}
		if v, ok := argVal.(string); ok {
			address := &aptos.AccountAddress{}
			err := address.ParseStringRelaxed(v)
			if err != nil {
				return err
			}
			address.MarshalBCS(serializer)
			return nil
		}
	case aptos.TypeTagVector:
		itemType := argType.Value.(*aptos.VectorTag).TypeParam
		switch itemType.Value.GetType() {
		case aptos.TypeTagU8:
			if v, ok := argVal.([]byte); ok {
				serializer.WriteBytes(v)
				return nil
			}
			if v, ok := argVal.(string); ok {
				serializer.WriteString(v)
				return nil
			}
		default:
		}

		rv := reflect.ValueOf(argVal)
		kindstring := rv.Kind().String()
		print(kindstring)
		if rv.Kind() != reflect.Array && rv.Kind() != reflect.Slice {
			return errors.New("invalid vector args")
		}
		length := rv.Len()
		serializer.Uleb128(uint32(length))
		for i := 0; i < length; i++ {
			if err := serializeArg(rv.Index(i).Interface(), itemType, serializer); err != nil {
				return err
			}
		}
		return nil
	case aptos.TypeTagStruct:
		tag := argType.Value.(*aptos.StructTag)
		if tag.String() != "0x1::string::String" {
			return errors.New("The only supported struct arg is of type 0x1::string::String")
		}
		if v, ok := argVal.(string); ok {
			serializer.WriteString(v)
			return nil
		}
	default:
		return errors.New("unsupported arg type")
	}
	return fmt.Errorf("invalid argument: %v", argVal)
}
