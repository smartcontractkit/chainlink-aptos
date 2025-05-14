package txm

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/stretchr/testify/require"
)

func TestCreateBcsValue(t *testing.T) {
	t.Parallel()
	t.Run("", func(t *testing.T) {
		address := &aptos.AccountAddress{}
		_ = address.ParseStringRelaxed("0x3b17dad1bdd88f337712cc2f6187bb741d56da467320373fd9198262cc93de76")
		stringAddress := address.StringLong()
		byteAddress, err := bcs.Serialize(address)
		require.NoError(t, err)
		typeTag, err := CreateTypeTag("address")
		require.NoError(t, err)

		// Test serializing a hex string value
		serialized, err := CreateBcsValue(typeTag, stringAddress)
		require.NoError(t, err)
		require.Equal(t, byteAddress, serialized)

		// Test serializing a base64 string
		// When marshalling using JSON, the bytearray will be serialized as a base64 string,
		// unmarshalling this string into an any will result in it being treated as a string, not a bytearray.
		// CreateBcsValue is supposed to account for this by first testing if the value can be decoded using base64
		marshaled, err := json.Marshal(struct {
			Address []byte `json:"address"`
		}{Address: byteAddress})
		require.NoError(t, err)
		result := make(map[string]interface{})
		err = json.Unmarshal(marshaled, &result)
		require.NoError(t, err)
		serialized, err = CreateBcsValue(typeTag, result["address"].(string))
		require.NoError(t, err)
		require.Equal(t, byteAddress, serialized)
	})
}

func TestGetBcsValues(t *testing.T) {
	t.Parallel()
	t.Run("uint32,uint64", func(t *testing.T) {
		t.Parallel()
		value1 := uint32(142)
		typeTag1, err := CreateTypeTag("u32")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, value1)
		require.NoError(t, err)

		value2 := uint64(14283123)
		typeTag2, err := CreateTypeTag("u64")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.Equal(t, decoded[0], value1)
		require.Equal(t, decoded[1], value2)
	})
	t.Run("uint128,string", func(t *testing.T) {
		t.Parallel()
		value1 := big.NewInt(128128128128128)
		typeTag1, err := CreateTypeTag("u128")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, value1)
		require.NoError(t, err)

		value2 := "thisisastring!"
		typeTag2, err := CreateTypeTag("0x1::string::String")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.Equal(t, decoded[0], value1)
		require.Equal(t, decoded[1], value2)
	})
	t.Run("address,[][]uint64", func(t *testing.T) {
		t.Parallel()
		value1 := aptos.AccountAddress{}
		_ = value1.ParseStringRelaxed("0x123456789")
		typeTag1, err := CreateTypeTag("address")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, value1)
		require.NoError(t, err)

		value2 := [][]uint64{{1, 2, 3}}
		typeTag2, err := CreateTypeTag("vector<vector<u64>>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.EqualValues(t, value1, decoded[0])
		require.EqualValues(t, value2, decoded[1])
	})
	t.Run("[]string,[]uint16", func(t *testing.T) {
		t.Parallel()
		value1 := []string{"thisisatest!", "andanotherone123"}
		typeTag1, err := CreateTypeTag("vector<0x1::string::String>")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, value1)
		require.NoError(t, err)

		value2 := [][]uint16{}
		typeTag2, err := CreateTypeTag("vector<vector<u16>>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.EqualValues(t, value1, decoded[0])
		require.EqualValues(t, value2, decoded[1])
	})
	t.Run("*uint8,*uint16", func(t *testing.T) {
		t.Parallel()
		value1 := uint8(1)
		typeTag1, err := CreateTypeTag("0x1::option::Option<u8>")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, &value1)
		require.NoError(t, err)

		var value2 *uint16
		typeTag2, err := CreateTypeTag("0x1::option::Option<u16>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.EqualValues(t, &value1, decoded[0])
		require.EqualValues(t, value2, decoded[1])
	})
	t.Run("*string,**big.Int", func(t *testing.T) {
		t.Parallel()
		value1 := "helloworld"
		typeTag1, err := CreateTypeTag("0x1::option::Option<0x1::string::String>")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, &value1)
		require.NoError(t, err)

		value2 := big.NewInt(1234567890)
		typeTag2, err := CreateTypeTag("0x1::option::Option<u256>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, &value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.EqualValues(t, &value1, decoded[0])
		require.EqualValues(t, &value2, decoded[1])
	})
	t.Run("**uint8,**uint8,*big.Int", func(t *testing.T) {
		t.Parallel()
		// optional **uint8 - set
		value1 := uint8(14)
		value1Ptr := &value1
		typeTag1, err := CreateTypeTag("0x1::option::Option<0x1::option::Option<u8>>")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, &value1Ptr)
		require.NoError(t, err)

		// optional **uint8 - unset
		var value2 *uint8
		typeTag2, err := CreateTypeTag("0x1::option::Option<0x1::option::Option<u8>>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, &value2)
		require.NoError(t, err)

		// normal *big.Int - should not be de(referenced) to **big.Int/big.Int
		value3 := big.NewInt(1234567890)
		typeTag3, err := CreateTypeTag("u256")
		require.NoError(t, err)
		encoded3, err := CreateBcsValue(typeTag3, value3)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)
		bcs = append(bcs, encoded3...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2, typeTag3)
		require.NoError(t, err)
		require.Len(t, decoded, 3)
		require.EqualValues(t, &value1Ptr, decoded[0])
		require.EqualValues(t, &value2, decoded[1])
		require.EqualValues(t, value3, decoded[2])
	})
	t.Run("*[]uint16,*[]uint32", func(t *testing.T) {
		t.Parallel()
		value1 := []uint16{1, 2, 3, 4, 5, 6, 7, 8, 9}
		typeTag1, err := CreateTypeTag("0x1::option::Option<vector<u16>>")
		require.NoError(t, err)
		encoded1, err := CreateBcsValue(typeTag1, &value1)
		require.NoError(t, err)

		var value2 *[]uint32
		typeTag2, err := CreateTypeTag("0x1::option::Option<vector<u32>>")
		require.NoError(t, err)
		encoded2, err := CreateBcsValue(typeTag2, value2)
		require.NoError(t, err)

		bcs := append(encoded1, encoded2...)

		decoded, err := GetBcsValues(bcs, typeTag1, typeTag2)
		require.NoError(t, err)
		require.Len(t, decoded, 2)
		require.EqualValues(t, &value1, decoded[0])
		require.EqualValues(t, value2, decoded[1])
	})
}
