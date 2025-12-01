package codec

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-viper/mapstructure/v2"
)

func DecodeAptosJsonArray(from []any, to ...any) error {
	if len(to) != len(from) {
		return fmt.Errorf("mismatched from/to arguments")
	}

	for i := range from {
		if err := DecodeAptosJsonValue(from[i], to[i]); err != nil {
			return fmt.Errorf("failed to decode value: %w", err)
		}
	}
	return nil
}

func DecodeAptosJsonValue(from any, to any) error {
	// If `to` is a pointer to `any`, directly assign the value
	toValue := reflect.ValueOf(to)
	if toValue.Kind() == reflect.Ptr && !toValue.IsNil() {
		toElem := toValue.Elem()
		if toElem.Kind() == reflect.Interface && toElem.Type() == reflect.TypeOf((*any)(nil)).Elem() {
			toElem.Set(reflect.ValueOf(from))
			return nil
		}
	}

	config := &mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			hexStringHook,
			numericStringHook,
			booleanHook,
			arrayHook,
			mapstructure.StringToTimeDurationHookFunc(),
		),
		Result:           to,
		WeaklyTypedInput: true,
		MatchName: func(mapKey, fieldName string) bool {
			// Aptos uses snake_case for field names, while Go uses CamelCase,
			// remove underscores from field names to match Aptos field names
			fieldName = strings.ReplaceAll(fieldName, "_", "")
			mapKey = strings.ReplaceAll(mapKey, "_", "")
			return strings.EqualFold(mapKey, fieldName)
		},
	}

	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return fmt.Errorf("failed to create decoder: %+w", err)
	}

	return decoder.Decode(from)
}

func hexStringHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.String {
		return data, nil
	}

	str, ok := data.(string)
	if !ok || !strings.HasPrefix(str, "0x") {
		return data, nil
	}

	str = strings.TrimPrefix(str, "0x")

	// Handle single-field struct case first by recursing via DecodeAptosJsonValue
	if t.Kind() == reflect.Struct && t.NumField() == 1 {
		field := t.Field(0)
		// Create a new zero value struct
		newStructVal := reflect.New(t).Elem()
		// Get a pointer to the field within the new struct
		fieldPtr := newStructVal.Field(0).Addr().Interface()

		// Recursively decode the original hex string data into the field pointer
		// DecodeAptosJsonValue will apply the appropriate hooks (including this one)
		// for the field's type.
		if err := DecodeAptosJsonValue(data, fieldPtr); err != nil {
			return nil, fmt.Errorf("failed decoding hex string for single-field struct %v field %s (%v): %w", t, field.Name, field.Type, err)
		}
		// Return the populated struct instance
		return newStructVal.Interface(), nil
	}

	switch t.Kind() {
	case reflect.String:
		return data, nil
	case reflect.Slice:
		if t.Elem().Kind() != reflect.Uint8 {
			return nil, fmt.Errorf("unsupported target slice element type for hex string conversion: %v", t.Elem().Kind())
		}
		if str == "" {
			// hex.DecodeString returns an error if the string is empty
			return []uint8{}, nil
		} else if len(str)%2 == 1 {
			// hex.DecodeString does not support odd length strings
			str = "0" + str
		}
		bytes, err := hex.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex string %q: %w", str, err)
		}
		return bytes, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(str, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hex to uint: %w", err)
		}
		if overflowUint(t, val) {
			return nil, fmt.Errorf("value %d overflows %v", val, t)
		}
		return reflect.ValueOf(val).Convert(t).Interface(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(str, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse hex to int: %w", err)
		}
		if overflowInt(t, val) {
			return nil, fmt.Errorf("value %d overflows %v", val, t)
		}
		return reflect.ValueOf(val).Convert(t).Interface(), nil
	case reflect.Ptr:
		if t == reflect.TypeOf((*big.Int)(nil)) {
			bi := new(big.Int)
			_, ok := bi.SetString(str, 16)
			if !ok {
				return nil, fmt.Errorf("failed to parse hex string as big.Int: %s", str)
			}
			return bi, nil
		}
		if t == reflect.TypeOf((*common.Address)(nil)) {
			addr := common.HexToAddress(str)
			return &addr, nil
		}
		if t == reflect.TypeOf((*common.Hash)(nil)) {
			hash := common.HexToHash(str)
			return &hash, nil
		}
	case reflect.Array:
		if t == reflect.TypeOf(common.Address{}) {
			addr := common.HexToAddress(str)
			return addr, nil
		}
		if t == reflect.TypeOf(common.Hash{}) {
			addr := common.HexToHash(str)
			return addr, nil
		}
		if t == reflect.TypeOf(aptos.AccountAddress{}) {
			addr := aptos.AccountAddress{}
			err := addr.ParseStringRelaxed(str)
			if err != nil {
				return nil, fmt.Errorf("failed to parse Aptos AccountAddress from string: %w", err)
			}
			return addr, nil
		}
		if t.Elem().Kind() == reflect.Uint8 {
			if str == "" {
				// hex.DecodeString returns an error if the string is empty
				return []uint8{}, nil
			} else if len(str)%2 == 1 {
				// hex.DecodeString does not support odd length strings
				str = "0" + str
			}
			bytes, err := hex.DecodeString(str)
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex string %q: %w", str, err)
			}
			if len(bytes) != t.Len() {
				return nil, fmt.Errorf("hex string %q has incorrect length for u8 array, got %d, expected %d", str, len(bytes), t.Len())
			}
			// Create array of the correct type and copy bytes into it
			arrayVal := reflect.New(t).Elem()
			reflect.Copy(arrayVal, reflect.ValueOf(bytes))
			return arrayVal.Interface(), nil
		}
		return nil, fmt.Errorf("unsupported target array element type for hex string conversion: %v", t.Elem().Kind())
	default:
	}

	return nil, fmt.Errorf("unsupported target type for hex string conversion: %v", t.Kind())
}

func numericStringHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	var str string
	switch v := data.(type) {
	case string:
		str = v
	case json.Number:
		str = v.String()
	default:
		return data, nil
	}

	if t.Kind() == reflect.Struct && t.NumField() == 1 {
		field := t.Field(0)
		newStructVal := reflect.New(t).Elem()
		fieldPtr := newStructVal.Field(0).Addr().Interface()

		// Decode the original numeric string data into the field pointer
		if err := DecodeAptosJsonValue(str, fieldPtr); err != nil {
			return nil, fmt.Errorf("failed decoding numeric string for single-field struct %v field %s (%v): %w", t, field.Name, field.Type, err)
		}
		return newStructVal.Interface(), nil
	}

	switch t.Kind() {
	case reflect.String:
		return str, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(str, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse string to int: %+w", err)
		}
		if overflowInt(t, val) {
			return nil, fmt.Errorf("value %d overflows %v", val, t)
		}
		return reflect.ValueOf(val).Convert(t).Interface(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(str, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse string to uint: %+w", err)
		}
		if overflowUint(t, val) {
			return nil, fmt.Errorf("value %d overflows %v", val, t)
		}
		return reflect.ValueOf(val).Convert(t).Interface(), nil
	case reflect.Float32, reflect.Float64:
		val, err := strconv.ParseFloat(str, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse string to float: %+w", err)
		}
		if overflowFloat(t, val) {
			return nil, fmt.Errorf("value %f overflows %v", val, t)
		}
		return reflect.ValueOf(val).Convert(t).Interface(), nil
	case reflect.Ptr:
		if t == reflect.TypeOf((*big.Int)(nil)) {
			bi := new(big.Int)
			_, ok := bi.SetString(str, 10)
			if !ok {
				return nil, fmt.Errorf("failed to parse string as big.Int: %s", str)
			}
			return bi, nil
		}
	default:
	}

	return nil, fmt.Errorf("unsupported target type for numeric string conversion: %v", t.Kind())
}

func booleanHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	if f.Kind() != reflect.Bool {
		return data, nil
	}

	boolValue, ok := data.(bool)
	if !ok {
		// This should technically not happen if f.Kind() == reflect.Bool
		return data, nil
	}

	// Handle single-field struct case first by recursing via DecodeAptosJsonValue
	if t.Kind() == reflect.Struct && t.NumField() == 1 {
		field := t.Field(0)
		newStructVal := reflect.New(t).Elem()
		fieldPtr := newStructVal.Field(0).Addr().Interface()

		// Decode the original boolean data into the field pointer
		if err := DecodeAptosJsonValue(data, fieldPtr); err != nil {
			return nil, fmt.Errorf("failed decoding boolean for single-field struct %v field %s (%v): %w", t, field.Name, field.Type, err)
		}
		return newStructVal.Interface(), nil
	}

	switch t.Kind() {
	case reflect.Bool:
		return boolValue, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if boolValue {
			return reflect.ValueOf(1).Convert(t).Interface(), nil
		}
		return reflect.ValueOf(0).Convert(t).Interface(), nil
	case reflect.Ptr:
		if t == reflect.TypeOf((*big.Int)(nil)) {
			if boolValue {
				return big.NewInt(1), nil
			}
			return big.NewInt(0), nil
		}
	default:
	}

	return nil, fmt.Errorf("unsupported target type for boolean conversion: %v", t.Kind())
}

func arrayHook(f reflect.Type, t reflect.Type, data interface{}) (interface{}, error) {
	fKind := f.Kind()
	if fKind != reflect.Slice && fKind != reflect.Array {
		return data, nil
	}

	if t.Kind() == reflect.Struct && t.NumField() == 1 {
		field := t.Field(0)
		newStructVal := reflect.New(t).Elem()
		fieldPtr := newStructVal.Field(0).Addr().Interface()

		// Decode the original boolean data into the field pointer
		if err := DecodeAptosJsonValue(data, fieldPtr); err != nil {
			return nil, fmt.Errorf("failed decoding boolean for single-field struct %v field %s (%v): %w", t, field.Name, field.Type, err)
		}
		return newStructVal.Interface(), nil
	}

	if t.Kind() != reflect.Slice {
		return data, nil
	}

	sourceSlice := reflect.ValueOf(data)
	targetSlice := reflect.MakeSlice(t, sourceSlice.Len(), sourceSlice.Cap())

	for i := range sourceSlice.Len() {
		sourceElem := sourceSlice.Index(i).Interface()
		targetElem := reflect.New(t.Elem()).Interface()

		if err := DecodeAptosJsonValue(sourceElem, targetElem); err != nil {
			return nil, fmt.Errorf("failed to decode array element at index %d: %+w", i, err)
		}

		targetSlice.Index(i).Set(reflect.ValueOf(targetElem).Elem())
	}

	return targetSlice.Interface(), nil
}

// TODO: modified from https://cs.opensource.google/go/go/+/master:src/reflect/type.go
// where OverflowInt, OverflowUint, OverflowFloat was added to reflect.Type, use it once we
// upgrade: https://go-review.googlesource.com/c/go/+/567296
func overflowFloat(t reflect.Type, x float64) bool {
	k := t.Kind()
	switch k {
	case reflect.Float32:
		return overflowFloat32(x)
	case reflect.Float64:
		return false
	default:
	}
	panic("reflect: OverflowFloat of non-float type " + t.String())
}

func overflowFloat32(x float64) bool {
	if x < 0 {
		x = -x
	}
	return math.MaxFloat32 < x && x <= math.MaxFloat64
}

func overflowInt(t reflect.Type, x int64) bool {
	k := t.Kind()
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bitSize := t.Size() * 8
		trunc := (x << (64 - bitSize)) >> (64 - bitSize)
		return x != trunc
	default:
	}
	panic("reflect: OverflowInt of non-int type " + t.String())
}

func overflowUint(t reflect.Type, x uint64) bool {
	k := t.Kind()
	switch k {
	case reflect.Uint, reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		bitSize := t.Size() * 8
		trunc := (x << (64 - bitSize)) >> (64 - bitSize)
		return x != trunc
	default:
	}
	panic("reflect: OverflowUint of non-uint type " + t.String())
}
