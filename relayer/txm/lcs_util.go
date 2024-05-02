package txm

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"

	txbuilder "github.com/coming-chat/go-aptos/transaction_builder"
	"github.com/coming-chat/lcs"
)

func createTypeTag(typeName string) (txbuilder.TypeTag, error) {
	parser, err := txbuilder.NewTypeTagParser(typeName)
	if err != nil {
		return nil, err
	}
	tag, err := parser.ParseTypeTag()
	if err != nil {
		return nil, err
	}
	return tag, nil
}

func createBcsValue(typeTag txbuilder.TypeTag, typeValue any) ([]byte, error) {
	var b bytes.Buffer
	encoder := lcs.NewEncoder(&b)
	err := serializeArg(typeValue, typeTag, encoder)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// copied from https://github.com/coming-chat/go-aptos-sdk/blob/c2468230eadcf531e6aaadf961ea1e7c13ab0693/transaction_builder/builder_util.go#L222
// we don't use it directly because this is only called from TransactionBuilderABI.BuildTransactionPayload, which requires supplying the ABI first.
func serializeArg(argVal any, argType txbuilder.TypeTag, encoder *lcs.Encoder) error {
	switch argType.(type) {
	case txbuilder.TypeTagBool:
		if v, ok := argVal.(bool); ok {
			return encoder.Encode(v)
		}
	case txbuilder.TypeTagU8:
		if v, ok := argVal.(uint8); ok {
			return encoder.Encode(v)
		}
		if v, ok := argVal.(int); ok && v == int(uint8(v)) {
			return encoder.Encode(uint8(v))
		}
		if v, ok := argVal.(float64); ok && v == float64(uint8(v)) {
			return encoder.Encode(uint8(v))
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 8)
			if err != nil {
				return err
			}
			return encoder.Encode(uint8(u))
		}
	case txbuilder.TypeTagU64:
		if v, ok := argVal.(uint64); ok {
			return encoder.Encode(v)
		}
		if v, ok := argVal.(int); ok && v >= 0 {
			return encoder.Encode(uint64(v))
		}
		if v, ok := argVal.(float64); ok && v >= 0 {
			return encoder.Encode(uint64(v))
		}
		if v, ok := argVal.(string); ok {
			u, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return err
			}
			return encoder.Encode(u)
		}
	case txbuilder.TypeTagU128:
		if v, ok := argVal.(txbuilder.Uint128); ok {
			return encoder.Encode(v)
		}
		if v, ok := argVal.(*big.Int); ok {
			return encoder.Encode(txbuilder.Uint128{v})
		}
		if v, ok := argVal.(int); ok && v >= 0 {
			return encoder.Encode(txbuilder.Uint128{big.NewInt(int64(v))})
		}
		if v, ok := argVal.(float64); ok && v >= 0 {
			return encoder.Encode(txbuilder.Uint128{big.NewInt(int64(v))})
		}
		if v, ok := argVal.(string); ok {
			if big, ok := big.NewInt(0).SetString(v, 10); ok {
				return encoder.Encode(txbuilder.Uint128{big})
			}
		}
	case txbuilder.TypeTagAddress:
		if v, ok := argVal.(txbuilder.AccountAddress); ok {
			return encoder.Encode(v)
		}
		if v, ok := argVal.(string); ok {
			addr, err := txbuilder.NewAccountAddressFromHex(v)
			if err != nil {
				return err
			}
			return encoder.Encode(addr)
		}
	case txbuilder.TypeTagVector:
		itemType := argType.(txbuilder.TypeTagVector).Value
		switch itemType.(type) {
		case txbuilder.TypeTagU8:
			if v, ok := argVal.([]byte); ok {
				return encoder.Encode(v)
			}
			if v, ok := argVal.(string); ok {
				return encoder.Encode(v)
			}
		}

		rv := reflect.ValueOf(argVal)
		kindstring := rv.Kind().String()
		print(kindstring)
		if rv.Kind() != reflect.Array && rv.Kind() != reflect.Slice {
			return errors.New("Invalid vector args.")
		}
		length := rv.Len()
		if err := encoder.EncodeUleb128(uint64(length)); err != nil {
			return err
		}
		for i := 0; i < length; i++ {
			if err := serializeArg(rv.Index(i).Interface(), itemType, encoder); err != nil {
				return err
			}
		}
		return nil
	case txbuilder.TypeTagStruct:
		tag := argType.(txbuilder.TypeTagStruct)
		if tag.ShortFunctionName() != "0x1::string::String" {
			return errors.New("The only supported struct arg is of type 0x1::string::String")
		}
		if v, ok := argVal.(string); ok {
			return encoder.Encode(v)
		}
	default:
		return errors.New("Unsupported arg type.")
	}
	return fmt.Errorf("Invalid argument %v.", argVal)
}
