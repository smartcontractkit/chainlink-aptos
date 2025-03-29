package txm

import (
	"encoding/json"
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
	case "u16":
		return aptos.TypeTag{Value: &aptos.U16Tag{}}, nil
	case "u32":
		return aptos.TypeTag{Value: &aptos.U32Tag{}}, nil
	case "u64":
		return aptos.TypeTag{Value: &aptos.U64Tag{}}, nil
	case "u128":
		return aptos.TypeTag{Value: &aptos.U128Tag{}}, nil
	case "u256":
		return aptos.TypeTag{Value: &aptos.U256Tag{}}, nil
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
	// support json.Number as arguments are passed as JSON when we are a LOOP plugin
	if v, ok := argVal.(json.Number); ok {
		argVal = v.String()
	}

	switch argType.Value.GetType() {
	case aptos.TypeTagBool:
		if v, ok := argVal.(bool); ok {
			serializer.Bool(v)
			return nil
		}
		if v, ok := argVal.(uint64); ok && (v == uint64(0) || v == uint64(1)) {
			serializer.Bool(v == uint64(1))
			return nil
		}

		if v, ok := argVal.(string); ok {
			if v == "1" || v == "true" {
				serializer.Bool(true)
				return nil
			}
			if v == "0" || v == "false" {
				serializer.Bool(false)
				return nil
			}
			return fmt.Errorf("invalid bool value: %s", v)
		}
	case aptos.TypeTagU8:
		if v, ok := argVal.(uint8); ok {
			serializer.U8(v)
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint8(v)) {
			serializer.U8(uint8(v))
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
	case aptos.TypeTagU16:
		if v, ok := argVal.(uint16); ok {
			serializer.U16(v)
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint16(v)) {
			serializer.U16(uint16(v))
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint16(v)) {
			serializer.U16(uint16(v))
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint16(v)) {
			serializer.U16(uint16(v))
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			serializer.U16(uint16(u))
			return nil
		}
	case aptos.TypeTagU32:
		if v, ok := argVal.(uint32); ok {
			serializer.U32(v)
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint32(v)) {
			serializer.U32(uint32(v))
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
		if v, ok := argVal.(uint64); ok {
			b := big.NewInt(0).SetUint64(v)
			serializer.U128(*b)
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
	case aptos.TypeTagU256:
		if v, ok := argVal.(*big.Int); ok {
			serializer.U256(*v)
			return nil
		}
		if v, ok := argVal.(uint64); ok {
			b := big.NewInt(0).SetUint64(v)
			serializer.U256(*b)
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 {
			b := big.NewInt(int64(v))
			serializer.U256(*b)
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 {
			b := big.NewInt(int64(v))
			serializer.U256(*b)
			return nil
		}
		if v, ok := argVal.(string); ok {
			if big, ok := big.NewInt(0).SetString(v, 10); ok {
				serializer.U256(*big)
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
	return errors.New("unsupported arg value type")
}

func GetBcsValues(data []byte, typeTags ...aptos.TypeTag) ([]any, error) {
	deserializer := bcs.NewDeserializer(data)
	returns := make([]any, len(typeTags))
	var err error
	for i, tag := range typeTags {
		returns[i], err = deserializeArg(tag, deserializer)
		if err != nil {
			return nil, err
		}
	}
	return returns, nil
}

func deserializeArg(argType aptos.TypeTag, deserializer *bcs.Deserializer) (any, error) {
	switch argType.Value.GetType() {
	case aptos.TypeTagBool:
		return deserializer.Bool(), nil
	case aptos.TypeTagU8:
		return deserializer.U8(), nil
	case aptos.TypeTagU16:
		return deserializer.U16(), nil
	case aptos.TypeTagU32:
		return deserializer.U32(), nil
	case aptos.TypeTagU64:
		return deserializer.U64(), nil
	case aptos.TypeTagU128:
		b := deserializer.U128()
		return &b, nil
	case aptos.TypeTagU256:
		b := deserializer.U256()
		return &b, nil
	case aptos.TypeTagAddress:
		address := aptos.AccountAddress{}
		deserializer.Struct(&address)
		return address, nil
	case aptos.TypeTagVector:
		length := deserializer.Uleb128()
		elementType := getType(argType.Value.(*aptos.VectorTag).TypeParam)
		returns := reflect.MakeSlice(reflect.SliceOf(elementType), 0, int(length))
		for range length {
			elem, err := deserializeArg(argType.Value.(*aptos.VectorTag).TypeParam, deserializer)
			if err != nil {
				return nil, err
			}
			returns = reflect.Append(returns, reflect.ValueOf(elem))
		}
		return returns.Interface(), nil
	case aptos.TypeTagStruct:
		tag := argType.Value.(*aptos.StructTag)
		if tag.String() == "0x1::string::String" {
			return deserializer.ReadString(), nil
		}
		return nil, errors.New("The only supported struct arg is of type 0x1::string::String")
	default:
		return nil, errors.New("unsupported arg type")
	}
}

func getType(typeTag aptos.TypeTag) reflect.Type {
	switch typeTag.Value.GetType() {
	case aptos.TypeTagBool:
		return reflect.TypeOf(false)
	case aptos.TypeTagU8:
		return reflect.TypeOf(uint8(0))
	case aptos.TypeTagU16:
		return reflect.TypeOf(uint16(0))
	case aptos.TypeTagU32:
		return reflect.TypeOf(uint32(0))
	case aptos.TypeTagU64:
		return reflect.TypeOf(uint64(0))
	case aptos.TypeTagU128:
		return reflect.TypeOf(big.NewInt(0))
	case aptos.TypeTagU256:
		return reflect.TypeOf(big.NewInt(0))
	case aptos.TypeTagAddress:
		return reflect.TypeOf(aptos.AccountAddress{})
	case aptos.TypeTagStruct:
		return reflect.TypeOf(string(""))
	case aptos.TypeTagVector:
		elementType := getType(typeTag.Value.(*aptos.VectorTag).TypeParam)
		return reflect.SliceOf(elementType)
	default:
		return nil
	}
}
