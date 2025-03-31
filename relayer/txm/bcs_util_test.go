package txm

import (
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

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
}
