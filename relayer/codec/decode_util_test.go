package codec_test

import (
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var DecodeAptosJsonValue = codec.DecodeAptosJsonValue
var DecodeAptosJsonArray = codec.DecodeAptosJsonArray

type TestChainSelector uint64

func TestDecodeAptosJsonValue(t *testing.T) {
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

	t.Run("map to custom type", func(t *testing.T) {
		type MessageWithSelector struct {
			Selector TestChainSelector
			Message  string
		}

		var result MessageWithSelector
		err := DecodeAptosJsonValue(map[string]any{"selector": "12345", "message": "test message"}, &result)
		assert.NoError(t, err)
		assert.Equal(t, TestChainSelector(12345), result.Selector)
		assert.Equal(t, "test message", result.Message)
	})

	t.Run("map with chain_selector", func(t *testing.T) {
		type ChainItem struct {
			ChainSelector TestChainSelector
		}

		var result ChainItem
		err := DecodeAptosJsonValue(map[string]any{"chain_selector": "4457093679053095497"}, &result)
		assert.NoError(t, err)
		assert.Equal(t, TestChainSelector(4457093679053095497), result.ChainSelector)
	})

	t.Run("map with chain_selector passed in as any", func(t *testing.T) {
		type chainItem struct {
			ChainSelector TestChainSelector
		}

		type anyStruct struct {
			value any
		}

		var result chainItem
		anyResult := &anyStruct{value: &result}
		err := DecodeAptosJsonValue(map[string]any{"chain_selector": "4457093679053095497"}, anyResult.value)
		assert.NoError(t, err)
		assert.Equal(t, TestChainSelector(4457093679053095497), result.ChainSelector)
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
	t.Run("Numeric String and Hex String to Custom Type (ChainSelector) and []byte", func(t *testing.T) {
		var (
			selector TestChainSelector
			data     []byte
		)
		// Pass pointers to the concrete types
		err := DecodeAptosJsonArray([]any{"55555", "0xbeef"}, &selector, &data)
		assert.NoError(t, err)
		assert.Equal(t, TestChainSelector(55555), selector)
		assert.Equal(t, []byte{0xbe, 0xef}, data)
	})

	t.Run("JSON Number and Hex String to Custom Type (ChainSelector) and Aptos Address", func(t *testing.T) {
		var (
			selector TestChainSelector
			addr     aptos.AccountAddress
		)
		err := DecodeAptosJsonArray([]any{float64(12345), "0xf00d"}, &selector, &addr)
		assert.NoError(t, err)
		assert.Equal(t, TestChainSelector(12345), selector)

		expectedAddr := aptos.AccountAddress{}
		err = expectedAddr.ParseStringRelaxed("0xf00d") // Error ignored as it's for test setup
		assert.NoError(t, err)
		assert.Equal(t, expectedAddr, addr)
	})
}
