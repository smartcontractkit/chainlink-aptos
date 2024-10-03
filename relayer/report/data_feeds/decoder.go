package data_feeds

import (
	"math/big"
)

type FeedReport struct {
	FeedId [32]byte
	Data   []byte
}

type Reports = []FeedReport

// TODO: improve this function
// This is ABI encoding - abi: "(bytes32 FeedID, bytes RawReport)[] Reports" (set in workflow)
// Encoded with: https://github.com/smartcontractkit/chainlink/blob/develop/core/services/relay/evm/cap_encoder.go
func Decode(data []byte) (Reports, error) {
	offset := 0

	// Skip the first 32 bytes (assertion)
	offset += 32

	// Read the count
	countBytes := data[offset : offset+32]
	count := new(big.Int).SetBytes(countBytes).Int64()
	offset += 32

	// Skip len * offsets table
	offset += int(count) * 32

	feedIDs := make([][]byte, 0, count)
	reports := make([][]byte, 0, count)

	for i := int64(0); i < count; i++ {
		// Read the feed_id (32 bytes)
		feedID := data[offset : offset+32]
		feedIDs = append(feedIDs, feedID)
		offset += 32

		// Skip the next 32 bytes (assertion)
		offset += 32

		// Read the length of the report (32 bytes)
		lengthBytes := data[offset : offset+32]
		length := new(big.Int).SetBytes(lengthBytes).Int64()
		offset += 32

		// Read the report data
		report := data[offset : offset+int(length)]
		reports = append(reports, report)
		offset += int(length)
	}

	// Create the Report struct
	reportData := make([]FeedReport, count)

	for i := int64(0); i < count; i++ {
		var feedID [32]byte
		copy(feedID[:], feedIDs[i])

		reportData[i] = FeedReport{
			FeedId: feedID,
			Data:   reports[i],
		}
	}

	return reportData, nil
}
