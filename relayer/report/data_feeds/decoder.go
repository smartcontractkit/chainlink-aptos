package data_feeds

import (
	"math/big"
)

type Report struct {
	Reports []FeedReport
}

type FeedReport struct {
	FeedId [32]byte
	Data   []byte
}

// TODO: improve this function
func Decode(data []byte) (*Report, error) {
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
	reportData := &Report{
		Reports: make([]FeedReport, count),
	}

	for i := int64(0); i < count; i++ {
		var feedID [32]byte
		copy(feedID[:], feedIDs[i])

		reportData.Reports[i] = FeedReport{
			FeedId: feedID,
			Data:   reports[i],
		}
	}

	return reportData, nil
}
