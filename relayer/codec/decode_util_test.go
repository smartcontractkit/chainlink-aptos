package codec

import (
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
)

func TestDecodeAptosJsonValue(t *testing.T) {
	t.Parallel()
	t.Run("String to String", func(t *testing.T) {
		var result string
		err := DecodeAptosJsonValue("hello world", &result)
		assert.NoError(t, err)
		assert.Equal(t, "hello world", result)
	})

	t.Run("Hex String to []byte", func(t *testing.T) {
		var result []byte
		err := DecodeAptosJsonValue("0x12345678", &result)
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x12, 0x34, 0x56, 0x78}, result)
	})

	t.Run("Uneven Hex String to []byte", func(t *testing.T) {
		var result []byte
		err := DecodeAptosJsonValue("0x1234567", &result)
		assert.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x23, 0x45, 0x67}, result)
	})

	t.Run("Hex String to *big.Int", func(t *testing.T) {
		var result *big.Int
		err := DecodeAptosJsonValue("0x12345678", &result)
		assert.NoError(t, err)
		expected := big.NewInt(0x12345678)
		if result.Cmp(expected) != 0 {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	t.Run("Array of Hex Strings to [][]byte", func(t *testing.T) {
		var result [][]byte
		err := DecodeAptosJsonValue([]interface{}{"0x1234", "0x5678"}, &result)
		assert.NoError(t, err)
		assert.Equal(t, [][]byte{{0x12, 0x34}, {0x56, 0x78}}, result)
	})

	t.Run("Array of Hex Strings to []*big.Int", func(t *testing.T) {
		var result []*big.Int
		err := DecodeAptosJsonValue([]interface{}{"0x1234", "0x5678"}, &result)
		assert.NoError(t, err)
		expected := []*big.Int{big.NewInt(0x1234), big.NewInt(0x5678)}
		if !compareBigIntSlices(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})

	// this can occur for example when returning a tuple of (u32, u64),
	// because u32 is encoded as a JSON number, where u64 is encoded as a JSON string.
	t.Run("Array of Mixed Types to []uint", func(t *testing.T) {
		var result []uint
		err := DecodeAptosJsonValue([]interface{}{42, "99"}, &result)
		assert.NoError(t, err)
		assert.Equal(t, []uint{42, 99}, result)
	})

	t.Run("Boolean to Boolean", func(t *testing.T) {
		var result bool
		err := DecodeAptosJsonValue(true, &result)
		assert.NoError(t, err)
		assert.True(t, result)

		err = DecodeAptosJsonValue(false, &result)
		assert.NoError(t, err)
		assert.False(t, result)
	})

	t.Run("Invalid Hex String", func(t *testing.T) {
		var result []byte
		err := DecodeAptosJsonValue("0xZZZZ", &result)
		assert.Error(t, err)
	})

	t.Run("Non-numeric String to Int", func(t *testing.T) {
		var result int
		err := DecodeAptosJsonValue("not a number", &result)
		assert.Error(t, err)
	})

	t.Run("Overflow Uint8", func(t *testing.T) {
		var result uint8
		err := DecodeAptosJsonValue("256", &result)
		assert.Error(t, err)
	})

	t.Run("Boolean to Unsupported Type", func(t *testing.T) {
		var result float64
		err := DecodeAptosJsonValue(true, &result)
		assert.Error(t, err)
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
		err := DecodeAptosJsonValue(input, &result)
		assert.NoError(t, err)
		if result.Name != "John" || result.Age != 30 || !compareBigIntSlices(result.Data, []*big.Int{big.NewInt(0x1234), big.NewInt(0x5678)}) {
			t.Errorf("Unexpected result: %+v", result)
		}
	})

	t.Run("Struct with snake_case fields", func(t *testing.T) {
		input := map[string]any{
			"first_name": "John",
			"last_name":  "Doe",
			"latestAge":  30,
		}
		var result struct {
			FirstName string
			LastName  string
			LatestAge int
		}
		err := DecodeAptosJsonValue(input, &result)
		assert.NoError(t, err)
		if result.FirstName != "John" || result.LastName != "Doe" || result.LatestAge != 30 {
			t.Errorf("Unexpected result: %+v", result)
		}
	})

	t.Run("String to Hash", func(t *testing.T) {
		var result *common.Hash
		err := DecodeAptosJsonValue("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", &result)
		assert.NoError(t, err)
		expected := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
		assert.Equal(t, expected, *result)
	})

	t.Run("String to Eth Address", func(t *testing.T) {
		var result common.Address
		err := DecodeAptosJsonValue("0x1234567890abcdef1234567890abcdef12345678", &result)
		assert.NoError(t, err)
		expected := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
		assert.Equal(t, expected, result)
	})

	t.Run("String to Aptos AccountAddress", func(t *testing.T) {
		var result aptos.AccountAddress
		err := DecodeAptosJsonValue("0x1", &result)
		assert.NoError(t, err)
		expected := aptos.AccountOne
		assert.Equal(t, expected, result)
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

func TestDecodeAptosJsonArray(t *testing.T) {
	t.Parallel()
	t.Run("string,string to string,string", func(t *testing.T) {
		var (
			firstWord  string
			secondWord string
		)
		err := DecodeAptosJsonArray([]any{"hello", "world"}, &firstWord, &secondWord)
		assert.NoError(t, err)
		assert.Equal(t, "hello", firstWord)
		assert.Equal(t, "world", secondWord)
	})
	t.Run("int,string to uint,uint", func(t *testing.T) {
		var (
			firstNumber  uint
			secondNumber uint
		)
		err := DecodeAptosJsonArray([]any{42, "99"}, &firstNumber, &secondNumber)
		assert.NoError(t, err)
		assert.EqualValues(t, 42, firstNumber)
		assert.EqualValues(t, 99, secondNumber)
	})
	t.Run("int,string to int,string", func(t *testing.T) {
		var (
			resInt int
			resStr string
		)
		err := DecodeAptosJsonArray([]any{42, "99"}, &resInt, &resStr)
		assert.NoError(t, err)
		assert.EqualValues(t, 42, resInt)
		assert.Equal(t, "99", resStr)
	})
	t.Run("string,string to int,*big.Int", func(t *testing.T) {
		var (
			resInt int
			resBig *big.Int
		)
		err := DecodeAptosJsonArray([]any{"42", "99"}, &resInt, &resBig)
		assert.NoError(t, err)
		assert.EqualValues(t, 42, resInt)
		if resBig.Cmp(big.NewInt(99)) != 0 {
			t.Errorf("Expected 99, got %v", resBig)
		}
	})
	t.Run("Nested structures", func(t *testing.T) {
		var (
			person struct {
				FirstName string
				LastName  string
			}
			age int
		)
		err := DecodeAptosJsonArray([]any{map[string]any{"first_name": "John", "last_name": "Doe"}, 30}, &person, &age)
		assert.NoError(t, err)
		assert.Equal(t, "John", person.FirstName)
		assert.Equal(t, "Doe", person.LastName)
		assert.EqualValues(t, 30, age)
	})
	t.Run("Invalid arguments", func(t *testing.T) {
		var result string
		err := DecodeAptosJsonArray([]any{"hello", "world"}, &result)
		assert.Error(t, err)
	})
	t.Run("Hex String to [32]uint8 Array", func(t *testing.T) {
		var result [32]uint8
		// 32-byte hex string (64 hex characters)
		hexStr := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
		err := DecodeAptosJsonValue(hexStr, &result)
		assert.NoError(t, err)
		expected := [32]uint8{
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
		}
		assert.Equal(t, expected, result)
	})

	t.Run("Hex String to [4]uint8 Array - Wrong Length", func(t *testing.T) {
		var result [4]uint8
		// Only 2 bytes, but array expects 4
		err := DecodeAptosJsonValue("0x1234", &result)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "incorrect length")
	})

	t.Run("Empty Hex String to [0]uint8 Array", func(t *testing.T) {
		var result [0]uint8
		err := DecodeAptosJsonValue("0x", &result)
		assert.NoError(t, err)
		expected := [0]uint8{}
		assert.Equal(t, expected, result)
	})
}
