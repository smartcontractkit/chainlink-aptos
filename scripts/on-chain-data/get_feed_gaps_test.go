package main

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildFeedGapRows(t *testing.T) {
	t.Parallel()

	// Window: observation timestamps 1200–2000 (inclusive for rows).
	// Fixture timeline:
	//   ts 1000 testFeed  -> before window; not exported, but sets gap for ts 1260
	//   ts 1260 testFeed  -> in window; gap 260 (1260-1000); 0xtx2 wins dedup
	//   ts 1500 testFeed  -> in window; gap 240
	//   ts 1300 otherfeed -> in window; first row for that feed (blank gap)
	windowStart := time.Unix(1200, 0).UTC()
	now := time.Unix(2000, 0).UTC()
	windowStartUnix := windowStart.Unix()

	feedEvents := []FeedUpdatedEventData{
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1000",
			BlockTimestamp:       "1740000000000000",
			TransactionHash:      "0xtx1",
			Benchmark:            "100",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1260",
			BlockTimestamp:       "1740000001000000",
			TransactionHash:      "0xtx2",
			Benchmark:            "101",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1260",
			BlockTimestamp:       "1740000002000000",
			TransactionHash:      "0xtx-dup",
			Benchmark:            "101",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1500",
			BlockTimestamp:       "1740000003000000",
			TransactionHash:      "0xtx3",
			Benchmark:            "102",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               "0xotherfeed000000000000000000000000000000000000000000000000000000",
			ObservationTimestamp: "1300",
			BlockTimestamp:       "1740000004000000",
			TransactionHash:      "0xtx4",
			Benchmark:            "200",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
	}

	rows, gapSummaries := buildFeedGapRows(feedEvents, windowStartUnix, now)

	// 3 total in-window rows: 2 for testFeed (1260, 1500) + 1 for otherfeed (1300).
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3 in-window observations", len(rows))
	}

	firstFeedRows := filterRowsByFeed(rows, testFeedID)
	if len(firstFeedRows) != 2 {
		t.Fatalf("got %d rows for test feed, want 2 (observation at 1000 is before window)", len(firstFeedRows))
	}
	if firstFeedRows[0].GapSinceLastUpdateS != "260" {
		t.Fatalf("first in-window row gap = %q, want 260 from pre-window observation", firstFeedRows[0].GapSinceLastUpdateS)
	}
	if firstFeedRows[0].TransactionHash != "0xtx2" {
		t.Fatalf("deduped tx = %q, want 0xtx2", firstFeedRows[0].TransactionHash)
	}
	if firstFeedRows[1].GapSinceLastUpdateS != "240" {
		t.Fatalf("second in-window row gap = %q, want 240", firstFeedRows[1].GapSinceLastUpdateS)
	}

	if len(gapSummaries) != 2 {
		t.Fatalf("got %d gap summaries, want 2", len(gapSummaries))
	}
	if gapSummaries[0].gapSeconds != 260 {
		t.Fatalf("largest gap = %d, want 260", gapSummaries[0].gapSeconds)
	}

	// Pre-window observations are excluded from CSV rows but still anchor gap calculation.
	preWindowEvents := []FeedUpdatedEventData{
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "900",
			BlockTimestamp:       "1739999990000000",
			TransactionHash:      "0xbefore",
			Benchmark:            "99",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1260",
			BlockTimestamp:       "1740000001000000",
			TransactionHash:      "0xtx2",
			Benchmark:            "101",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
	}

	preWindowRows, preWindowGaps := buildFeedGapRows(preWindowEvents, windowStartUnix, now)
	if len(preWindowRows) != 1 {
		t.Fatalf("got %d rows with pre-window context, want 1", len(preWindowRows))
	}
	if preWindowRows[0].GapSinceLastUpdateS != "360" {
		t.Fatalf("in-window row gap = %q, want 360 from pre-window observation", preWindowRows[0].GapSinceLastUpdateS)
	}
	if len(preWindowGaps) != 1 || preWindowGaps[0].gapSeconds != 360 {
		t.Fatalf("gap summaries = %+v, want one 360s gap", preWindowGaps)
	}
}

func TestBuildFeedGapRowsEmpty(t *testing.T) {
	t.Parallel()

	rows, gapSummaries := buildFeedGapRows(nil, 1200, time.Unix(2000, 0).UTC())
	if len(rows) != 0 || len(gapSummaries) != 0 {
		t.Fatalf("expected empty result, got rows=%d summaries=%d", len(rows), len(gapSummaries))
	}
}

func TestBuildFeedGapRowsSorting(t *testing.T) {
	t.Parallel()

	feedEvents := []FeedUpdatedEventData{
		{
			FeedId:               "0xfeedb000000000000000000000000000000000000000000000000000000000",
			ObservationTimestamp: "1300",
			BlockTimestamp:       "1740000004000000",
			TransactionHash:      "0xtx-b",
			Benchmark:            "200",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1260",
			BlockTimestamp:       "1740000001000000",
			TransactionHash:      "0xtx-a",
			Benchmark:            "101",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
	}

	rows, _ := buildFeedGapRows(feedEvents, 1200, time.Unix(2000, 0).UTC())
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].FeedID != testFeedID || rows[1].FeedID != "0xfeedb000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("rows not sorted by feed id: %+v", rows)
	}
}

func TestBuildFeedGapRowsInvalidTimestampsSkipped(t *testing.T) {
	t.Parallel()

	feedEvents := []FeedUpdatedEventData{
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "not-a-number",
			BlockTimestamp:       "1740000000000000",
			TransactionHash:      "0xbad",
			Benchmark:            "100",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
		{
			FeedId:               testFeedID,
			ObservationTimestamp: "1260",
			BlockTimestamp:       "1740000001000000",
			TransactionHash:      "0xgood",
			Benchmark:            "101",
			TransactionSuccess:   true,
			TransactionGasUsed:   "50",
		},
	}

	rows, gapSummaries := buildFeedGapRows(feedEvents, 1200, time.Unix(2000, 0).UTC())
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1 valid row", len(rows))
	}
	if len(gapSummaries) != 0 {
		t.Fatalf("got %d gap summaries, want 0 with only one valid observation", len(gapSummaries))
	}
	if rows[0].TransactionHash != "0xgood" {
		t.Fatalf("row tx = %q, want 0xgood", rows[0].TransactionHash)
	}
}

func TestRunGetFeedGapsInvalidMinutes(t *testing.T) {
	t.Parallel()

	if err := runGetFeedGaps("mainnet", 0); err == nil {
		t.Fatal("expected error for zero minutes")
	}
	if err := runGetFeedGaps("mainnet", -5); err == nil {
		t.Fatal("expected error for negative minutes")
	}
}

func TestSummarizeFeedGapsNoGaps(t *testing.T) {
	t.Parallel()

	rows := []FeedGapRow{
		{FeedID: testFeedID, GapSinceLastUpdateS: ""},
	}
	stats := summarizeFeedGaps(nil, rows)
	if len(stats) != 1 {
		t.Fatalf("got %d feed stats, want 1", len(stats))
	}
	if stats[0].updates != 1 || stats[0].gaps != 0 || stats[0].maxGap != 0 {
		t.Fatalf("stats = %+v, want one update and zero gaps", stats[0])
	}
}

func TestSummarizeFeedGaps(t *testing.T) {
	t.Parallel()

	rows := []FeedGapRow{
		{FeedID: testFeedID, GapSinceLastUpdateS: ""},
		{FeedID: testFeedID, GapSinceLastUpdateS: "260"},
		{FeedID: testFeedID, GapSinceLastUpdateS: "240"},
	}
	gapSummaries := []feedGapSummary{
		{feedID: testFeedID, gapSeconds: 260},
		{feedID: testFeedID, gapSeconds: 240},
	}

	stats := summarizeFeedGaps(gapSummaries, rows)
	if len(stats) != 1 {
		t.Fatalf("got %d feed stats, want 1", len(stats))
	}
	if stats[0].updates != 3 || stats[0].gaps != 2 {
		t.Fatalf("updates=%d gaps=%d, want 3 and 2", stats[0].updates, stats[0].gaps)
	}
	if stats[0].minGap != 240 || stats[0].maxGap != 260 {
		t.Fatalf("min=%d max=%d, want 240 and 260", stats[0].minGap, stats[0].maxGap)
	}
}

func TestWriteFeedGapsCSV(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "gaps.csv")
	rows := []FeedGapRow{
		{
			FeedID:               testFeedID,
			ObservationTimestamp: 1260,
			ObservationTimeUTC:   "2026-05-28 11:31:30",
			GapSinceLastUpdateS:  "260",
			BlockTimestamp:       1740000001000000,
			BlockTimeUTC:         "2026-05-28 11:31:31.000000",
			TransactionHash:      "0xtx2",
			Benchmark:            "101",
			Success:              true,
			GasUsed:              "50",
		},
	}

	if err := writeFeedGapsCSV(path, rows); err != nil {
		t.Fatalf("writeFeedGapsCSV() error: %v", err)
	}

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open() error: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want header + 1 row", len(records))
	}
	if records[1][0] != testFeedID || records[1][3] != "260" {
		t.Fatalf("row = %v, unexpected values", records[1])
	}
}

func TestFormatUnixTimestamps(t *testing.T) {
	t.Parallel()

	if got := formatUnixSecondsUTC(1740000000); got != time.Unix(1740000000, 0).UTC().Format("2006-01-02 15:04:05") {
		t.Fatalf("formatUnixSecondsUTC() = %q", got)
	}

	if got := formatUnixMicrosUTC(1740000001234567); got != time.Unix(1740000001, 234567000).UTC().Format("2006-01-02 15:04:05.000000") {
		t.Fatalf("formatUnixMicrosUTC() = %q", got)
	}
}

func filterRowsByFeed(rows []FeedGapRow, feedID string) []FeedGapRow {
	var filtered []FeedGapRow
	for _, row := range rows {
		if row.FeedID == feedID {
			filtered = append(filtered, row)
		}
	}
	return filtered
}
