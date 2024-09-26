package data_feeds

import (
	"encoding/hex"
	"math/big"
)

type Report struct {
	Reports []FeedReport
}

type FeedReport struct {
	FeedID string
	Data   []byte
}

func DecodeReport(data []byte) Report {
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
	reportData := Report{
		Reports: make([]FeedReport, count),
	}

	for i := int64(0); i < count; i++ {
		reportData.Reports[i] = FeedReport{
			FeedID: "0x" + hex.EncodeToString(feedIDs[i]),
			Data:   reports[i],
		}
	}

	return reportData
}
