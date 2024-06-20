package chainreader

import (
	"math/big"
	"reflect"
	"testing"
)

func TestDecodeAptosJsonValue(t *testing.T) {
	t.Run("String to String", func(t *testing.T) {
		var result string
		err := decodeAptosJsonValue("hello world", &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result != "hello world" {
			t.Errorf("Expected 'hello world', got '%s'", result)
		}
	})

	t.Run("Hex String to []byte", func(t *testing.T) {
		var result []byte
		err := decodeAptosJsonValue("0x12345678", &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expected := []byte{0x12, 0x34, 0x56, 0x78}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("Hex String to *big.Int", func(t *testing.T) {
		var result *big.Int
		err := decodeAptosJsonValue("0x12345678", &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expected := big.NewInt(0x12345678)
		if result.Cmp(expected) != 0 {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("Array of Hex Strings to [][]byte", func(t *testing.T) {
		var result [][]byte
		err := decodeAptosJsonValue([]interface{}{"0x1234", "0x5678"}, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expected := [][]byte{{0x12, 0x34}, {0x56, 0x78}}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("Array of Hex Strings to []*big.Int", func(t *testing.T) {
		var result []*big.Int
		err := decodeAptosJsonValue([]interface{}{"0x1234", "0x5678"}, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expected := []*big.Int{big.NewInt(0x1234), big.NewInt(0x5678)}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// this can occur for example when returning a tuple of (u32, u64),
	// because u32 is encoded as a JSON number, where u64 is encoded as a JSON string.
	t.Run("Array of Mixed Types to []uint", func(t *testing.T) {
		var result []uint
		err := decodeAptosJsonValue([]interface{}{42, "99"}, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expected := []uint{42, 99}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("Boolean to Boolean", func(t *testing.T) {
		var result bool
		err := decodeAptosJsonValue(true, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !result {
			t.Errorf("Expected true, got false")
		}

		err = decodeAptosJsonValue(false, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result {
			t.Errorf("Expected false, got true")
		}
	})

	t.Run("Invalid Hex String", func(t *testing.T) {
		var result []byte
		err := decodeAptosJsonValue("0xZZZZ", &result)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Non-numeric String to Int", func(t *testing.T) {
		var result int
		err := decodeAptosJsonValue("not a number", &result)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Overflow Uint8", func(t *testing.T) {
		var result uint8
		err := decodeAptosJsonValue("256", &result)
		if err == nil {
			t.Fatalf("Expected an error, got nil")
		}
	})

	t.Run("Boolean to Unsupported Type", func(t *testing.T) {
		var result float64
		err := decodeAptosJsonValue(true, &result)
		if err == nil {
			t.Fatalf("Expected an error or no conversion, got %v", result)
		}
	})

	t.Run("Nested Structures", func(t *testing.T) {
		input := map[string]interface{}{
			"name": "John",
			"age":  "30",
			"data": []interface{}{"0x1234", "0x5678"},
		}
		var result struct {
			Name string
			Age  int
			Data []*big.Int
		}
		err := decodeAptosJsonValue(input, &result)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if result.Name != "John" || result.Age != 30 || !compareBigIntSlices(result.Data, []*big.Int{big.NewInt(0x1234), big.NewInt(0x5678)}) {
			t.Errorf("Unexpected result: %+v", result)
		}
	})
}

func compareBigIntSlices(a, b []*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}
