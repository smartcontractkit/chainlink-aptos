package txm

import (
	"encoding/base64"
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
			// Assume it's a struct - split into the first three substrings
			// There might be multiple nested structs such as 0x1::option::Option<0x1::string::String>
			structTokens := strings.SplitN(typeName, "::", 3)
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
				// TODO this would currently not work with nested structs
				//  E.g. 0x1::module::Name<u8,0x1::module::Name<u16,u32>>
				//
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

	// this should never occur, as we should check for serialize errors after every invocation.
	if err := serializer.Error(); err != nil {
		return nil, fmt.Errorf("unexpected unchecked serialize error: %w", err)
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
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok && (v == uint64(0) || v == uint64(1)) {
			serializer.Bool(v == uint64(1))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}

		if v, ok := argVal.(string); ok {
			if v == "1" || v == "true" {
				serializer.Bool(true)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
			if v == "0" || v == "false" {
				serializer.Bool(false)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
			return fmt.Errorf("invalid bool value: %s", v)
		}
	case aptos.TypeTagU8:
		if v, ok := argVal.(uint8); ok {
			serializer.U8(v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint8(v)) {
			serializer.U8(uint8(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint8(v)) {
			serializer.U8(uint8(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint8(v)) {
			serializer.U8(uint8(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return err
			}
			serializer.U8(uint8(u))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
	case aptos.TypeTagU16:
		if v, ok := argVal.(uint16); ok {
			serializer.U16(v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint16(v)) {
			serializer.U16(uint16(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint16(v)) {
			serializer.U16(uint16(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint16(v)) {
			serializer.U16(uint16(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return err
			}
			serializer.U16(uint16(u))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
	case aptos.TypeTagU32:
		if v, ok := argVal.(uint32); ok {
			serializer.U32(v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok && v == uint64(uint32(v)) {
			serializer.U32(uint32(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v == int(uint32(v)) {
			serializer.U32(uint32(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v == float64(uint32(v)) {
			serializer.U32(uint32(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return err
			}
			serializer.U32(uint32(u))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
	case aptos.TypeTagU64:
		if v, ok := argVal.(uint64); ok {
			serializer.U64(v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 && v == int(uint64(v)) {
			serializer.U64(uint64(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 && v == float64(uint64(v)) {
			serializer.U64(uint64(v))
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return err
			}
			serializer.U64(u)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
	case aptos.TypeTagU128:
		if v, ok := argVal.(*big.Int); ok {
			serializer.U128(*v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok {
			b := big.NewInt(0).SetUint64(v)
			serializer.U128(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 && v == int(int64(v)) {
			b := big.NewInt(int64(v))
			serializer.U128(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 && v == float64(int64(v)) {
			b := big.NewInt(int64(v))
			serializer.U128(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			if big, ok := big.NewInt(0).SetString(v, 10); ok {
				serializer.U128(*big)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
		}
	case aptos.TypeTagU256:
		if v, ok := argVal.(*big.Int); ok {
			serializer.U256(*v)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(uint64); ok {
			b := big.NewInt(0).SetUint64(v)
			serializer.U256(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(int); ok && v >= 0 && v == int(int64(v)) {
			b := big.NewInt(int64(v))
			serializer.U256(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(float64); ok && v >= 0 && v == float64(int64(v)) {
			b := big.NewInt(int64(v))
			serializer.U256(*b)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			if big, ok := big.NewInt(0).SetString(v, 10); ok {
				serializer.U256(*big)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
		}
	case aptos.TypeTagAddress:
		if v, ok := argVal.(aptos.AccountAddress); ok {
			v.MarshalBCS(serializer)
			if err := serializer.Error(); err != nil {
				return err
			}
			return nil
		}
		if v, ok := argVal.(string); ok {
			// first, check if it's base64
			decoded, err := base64.StdEncoding.DecodeString(v)
			if err == nil && len(decoded) == 32 {
				address := aptos.AccountAddress(decoded)
				address.MarshalBCS(serializer)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			} else {
				address := &aptos.AccountAddress{}
				err := address.ParseStringRelaxed(v)
				if err != nil {
					return err
				}
				address.MarshalBCS(serializer)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
		}
	case aptos.TypeTagVector:
		itemType := argType.Value.(*aptos.VectorTag).TypeParam
		switch itemType.Value.GetType() {
		case aptos.TypeTagU8:
			if v, ok := argVal.([]byte); ok {
				serializer.WriteBytes(v)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
			if v, ok := argVal.(string); ok {
				serializer.WriteString(v)
				if err := serializer.Error(); err != nil {
					return err
				}
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
		if err := serializer.Error(); err != nil {
			return err
		}

		for i := 0; i < length; i++ {
			if err := serializeArg(rv.Index(i).Interface(), itemType, serializer); err != nil {
				return err
			}

			if err := serializer.Error(); err != nil {
				return fmt.Errorf("unexpected unchecked serialize error while processing vector: %w", err)
			}
		}
		return nil
	case aptos.TypeTagStruct:
		tag := argType.Value.(*aptos.StructTag)
		// Can't use tag.String() as it would contain type parameters
		tagName := fmt.Sprintf("%s::%s::%s", tag.Address.String(), tag.Module, tag.Name)
		switch tagName {
		case "0x1::string::String":
			if v, ok := argVal.(string); ok {
				serializer.WriteString(v)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			}
		case "0x1::option::Option":
			rv := reflect.ValueOf(argVal)
			if rv.Kind() != reflect.Pointer {
				return fmt.Errorf("invalid arg for 0x1::option::Option, want %q, have: %q", reflect.Pointer.String(), rv.Kind().String())
			}
			if len(tag.TypeParams) != 1 {
				return errors.New("invalid option::Option type parameters")
			}
			if rv.IsNil() {
				// If the option is unset/nil pointer is passed, serialize as an empty vector
				serializer.Uleb128(0)
				if err := serializer.Error(); err != nil {
					return err
				}
				return nil
			} else {
				// If the option is set/a value is passed, serialize as a vector of length 1
				serializer.Uleb128(1)
				if err := serializer.Error(); err != nil {
					return err
				}
				if err := serializeArg(rv.Elem().Interface(), tag.TypeParams[0], serializer); err != nil {
					return err
				}
				if err := serializer.Error(); err != nil {
					return fmt.Errorf("unexpected unchecked serialize error while processing option: %w", err)
				}
				return nil
			}
		default:
			return fmt.Errorf("unsupported struct tag: %s", tagName)
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

		// this should never occur, as we should check for serialize errors after every invocation.
		if err := deserializer.Error(); err != nil {
			return nil, fmt.Errorf("unexpected unchecked deserialize error: %w", err)
		}
	}
	return returns, nil
}

func deserializeArg(argType aptos.TypeTag, deserializer *bcs.Deserializer) (any, error) {
	switch argType.Value.GetType() {
	case aptos.TypeTagBool:
		result := deserializer.Bool()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return result, nil
	case aptos.TypeTagU8:
		result := deserializer.U8()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return result, nil
	case aptos.TypeTagU16:
		result := deserializer.U16()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return result, nil
	case aptos.TypeTagU32:
		result := deserializer.U32()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return result, nil
	case aptos.TypeTagU64:
		result := deserializer.U64()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return result, nil
	case aptos.TypeTagU128:
		b := deserializer.U128()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return &b, nil
	case aptos.TypeTagU256:
		b := deserializer.U256()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return &b, nil
	case aptos.TypeTagAddress:
		address := aptos.AccountAddress{}
		deserializer.Struct(&address)
		if err := deserializer.Error(); err != nil {
			return nil, err
		}
		return address, nil
	case aptos.TypeTagVector:
		length := deserializer.Uleb128()
		if err := deserializer.Error(); err != nil {
			return nil, err
		}

		elementType := getType(argType.Value.(*aptos.VectorTag).TypeParam)
		returns := reflect.MakeSlice(reflect.SliceOf(elementType), 0, int(length))
		for range length {
			elem, err := deserializeArg(argType.Value.(*aptos.VectorTag).TypeParam, deserializer)
			if err != nil {
				return nil, err
			}

			// this should never occur, as we should check for deserialize errors after every invocation.
			if err := deserializer.Error(); err != nil {
				return nil, fmt.Errorf("unexpected unchecked deserialize error while processing vector: %w", err)
			}
			returns = reflect.Append(returns, reflect.ValueOf(elem))
		}
		return returns.Interface(), nil
	case aptos.TypeTagStruct:
		tag := argType.Value.(*aptos.StructTag)
		// Can't use tag.String() as it would contain type parameters
		tagName := fmt.Sprintf("%s::%s::%s", tag.Address.String(), tag.Module, tag.Name)
		switch tagName {
		case "0x1::string::String":
			result := deserializer.ReadString()
			if err := deserializer.Error(); err != nil {
				return nil, err
			}
			return result, nil
		case "0x1::option::Option":
			if len(tag.TypeParams) != 1 {
				return nil, errors.New("invalid option::Option type parameters")
			}
			length := deserializer.Uleb128()
			if err := deserializer.Error(); err != nil {
				return nil, err
			}
			if length == 0 {
				// Unset option - return a new nil pointer of the underlying type
				vp := reflect.NewAt(getType(tag.TypeParams[0]), nil)
				return vp.Interface(), nil
			} else if length == 1 {
				// Option is set - deserialize the underlying value and return a new pointer to it
				elem, err := deserializeArg(tag.TypeParams[0], deserializer)
				if err != nil {
					return nil, err
				}
				if err := deserializer.Error(); err != nil {
					return nil, fmt.Errorf("unexpected unchecked deserialize error while processing option: %w", err)
				}
				val := reflect.ValueOf(elem)
				vp := reflect.New(val.Type())
				vp.Elem().Set(val)
				return vp.Interface(), nil
			}
			return nil, fmt.Errorf("deserializing 0x1::option::Option: received invalid serialized vector of length %v", length)
		}
		return nil, fmt.Errorf("unsupported struct tag: %s", tagName)
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
		tag := typeTag.Value.(*aptos.StructTag)
		// Can't use tag.String() as it would contain type parameters
		tagName := fmt.Sprintf("%s::%s::%s", tag.Address.String(), tag.Module, tag.Name)
		switch tagName {
		case "0x1::string::String":
			return reflect.TypeOf(string(""))
		case "0x1::option::Option":
			if len(tag.TypeParams) != 1 {
				return nil
			}
			return reflect.PointerTo(getType(tag.TypeParams[0]))
		}
		return nil
	case aptos.TypeTagVector:
		elementType := getType(typeTag.Value.(*aptos.VectorTag).TypeParam)
		return reflect.SliceOf(elementType)
	default:
		return nil
	}
}
