package llo_test

import (
	"math/big"
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/relayer/report/llo"
	"github.com/stretchr/testify/require"
)

func TestDecodeFeedReport(t *testing.T) {
	// Create some sample records.
	original := []llo.Report{
		{
			// Example feedID: the first byte is 0x01 and the remainder are zeros.
			RemappedID: [32]byte{0x01},
			Price:      big.NewInt(1234567890123456789),
			Timestamp:  1620000000,
		},
		{
			RemappedID: [32]byte{0xAA, 0xBB, 0xCC},
			Price:      big.NewInt(123),
			Timestamp:  1630000000,
		},
	}

	// Get the ABI schema from our constructor.
	schema := llo.GetSchema()

	// Pack the original data using the ABI schema.
	encoded, err := schema.Pack(original)
	require.NoError(t, err, "failed to pack data")

	// Decode the data using our Decode function.
	decoded, err := llo.Decode(encoded)
	require.NoError(t, err, "failed to decode data")

	// Check that the lengths match.
	require.Equal(t, len(*decoded), len(original), "decoded length does not match original length")

	// Compare each record field by field.
	for i := range original {
		origRecord := original[i]
		decRecord := (*decoded)[i]

		// Compare FeedID.
		require.Equal(t, origRecord.RemappedID, decRecord.RemappedID, "FeedID mismatch")

		// Compare Price using big.Int.Cmp.
		require.Equal(t, origRecord.Price.String(), decRecord.Price.String(), "Price mismatch")

		// Compare Timestamp.
		require.Equal(t, origRecord.Timestamp, decRecord.Timestamp, "Timestamp mismatch")
	}
}
