package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testFeedID = "0x011e22d6bf000332000000000000000000000000000000000000000000000000"

func TestNormalizeFeedID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{testFeedID, testFeedID},
		{"011e22d6bf000332000000000000000000000000000000000000000000000000", testFeedID},
		{"  " + testFeedID + "  ", testFeedID},
	}

	for _, tt := range tests {
		if got := normalizeFeedID(tt.input); got != tt.want {
			t.Fatalf("normalizeFeedID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFindHeartbeatBreaches(t *testing.T) {
	t.Parallel()

	// Most mainnet feeds use a 255s heartbeat; gaps of 260s are the nominal ~5s overrun.
	feedConfig := FeedHeartbeatConfig{
		StreamID:  "1044000004",
		FeedID:    testFeedID,
		Heartbeat: 255,
	}

	t.Run("no data", func(t *testing.T) {
		breaches, summary := findHeartbeatBreaches(feedConfig, nil)
		if len(breaches) != 0 {
			t.Fatalf("expected no breaches, got %d", len(breaches))
		}
		if summary.Status != "NO_DATA" {
			t.Fatalf("status = %q, want NO_DATA", summary.Status)
		}
	})

	t.Run("single observation is ok", func(t *testing.T) {
		observations := []heartbeatObservation{{observationTimestamp: 1000, transactionHash: "0xabc"}}
		breaches, summary := findHeartbeatBreaches(feedConfig, observations)

		if len(breaches) != 0 {
			t.Fatalf("expected no breaches, got %d", len(breaches))
		}
		if summary.Status != "OK" {
			t.Fatalf("status = %q, want OK", summary.Status)
		}
		if summary.UpdateCount != 1 || summary.GapCount != 0 {
			t.Fatalf("updates=%d gaps=%d, want 1 and 0", summary.UpdateCount, summary.GapCount)
		}
	})

	t.Run("gap equal to heartbeat is ok", func(t *testing.T) {
		// Breach requires gap > heartbeat, not >=.
		observations := []heartbeatObservation{
			{observationTimestamp: 1000, transactionHash: "0x1"},
			{observationTimestamp: 1255, transactionHash: "0x2"},
		}
		breaches, summary := findHeartbeatBreaches(feedConfig, observations)

		if len(breaches) != 0 {
			t.Fatalf("expected no breaches at exactly heartbeat, got %d", len(breaches))
		}
		if summary.Status != "OK" {
			t.Fatalf("status = %q, want OK", summary.Status)
		}
		if summary.MaxGapSeconds != 255 {
			t.Fatalf("max gap = %d, want 255", summary.MaxGapSeconds)
		}
	})

	t.Run("gap over heartbeat is breached", func(t *testing.T) {
		observations := []heartbeatObservation{
			{observationTimestamp: 1000, transactionHash: "0x1"},
			{observationTimestamp: 1260, transactionHash: "0x2"},
		}
		breaches, summary := findHeartbeatBreaches(feedConfig, observations)

		if len(breaches) != 1 {
			t.Fatalf("expected 1 breach, got %d", len(breaches))
		}
		if summary.Status != "BREACHED" || summary.BreachCount != 1 {
			t.Fatalf("status=%q breaches=%d, want BREACHED and 1", summary.Status, summary.BreachCount)
		}
		if breaches[0].GapSeconds != 260 {
			t.Fatalf("gap = %d, want 260", breaches[0].GapSeconds)
		}
		if breaches[0].PreviousObsTimestamp != 1000 || breaches[0].CurrentObsTimestamp != 1260 {
			t.Fatalf("unexpected breach timestamps: %+v", breaches[0])
		}
	})

	t.Run("multiple breaches", func(t *testing.T) {
		// Gaps: 260 (breach), 240 (ok), 300 (breach).
		observations := []heartbeatObservation{
			{observationTimestamp: 1000, transactionHash: "0x1"},
			{observationTimestamp: 1260, transactionHash: "0x2"},
			{observationTimestamp: 1500, transactionHash: "0x3"},
			{observationTimestamp: 1800, transactionHash: "0x4"},
		}
		breaches, summary := findHeartbeatBreaches(feedConfig, observations)

		if len(breaches) != 2 {
			t.Fatalf("expected 2 breaches, got %d", len(breaches))
		}
		if summary.GapCount != 3 || summary.BreachCount != 2 {
			t.Fatalf("gaps=%d breaches=%d, want 3 and 2", summary.GapCount, summary.BreachCount)
		}
	})
}

func TestReadObservationsByFeed(t *testing.T) {
	t.Parallel()

	// Fixture layout:
	//   ts 1000 testFeed  -> kept
	//   ts 1260 testFeed  -> kept (0xtx2 wins dedup over 0xtx-dup)
	//   ts 1500 testFeed  -> kept
	//   ts 1300 otherfeed -> filtered out (not in feedIDs)
	csvPath := writeTestEventsCSV(t, [][]string{
		{"true", "executed successfully", "0xtx1", "100", "1740000000000000", "1000", testFeedID, "100"},
		{"true", "executed successfully", "0xtx2", "100", "1740000001000000", "1260", testFeedID, "101"},
		{"true", "executed successfully", "0xtx-dup", "100", "1740000002000000", "1260", testFeedID, "101"},
		{"true", "executed successfully", "0xtx3", "100", "1740000003000000", "1500", testFeedID, "102"},
		{"true", "executed successfully", "0xtx4", "100", "1740000004000000", "1300", "0xotherfeed000000000000000000000000000000000000000000000000000000", "200"},
	})

	feedIDs := map[string]struct{}{testFeedID: {}}
	observationsByFeed, err := readObservationsByFeed(csvPath, feedIDs)
	if err != nil {
		t.Fatalf("readObservationsByFeed() error: %v", err)
	}

	observations := observationsByFeed[testFeedID]
	if len(observations) != 3 {
		t.Fatalf("got %d observations, want 3", len(observations))
	}
	if observations[0].observationTimestamp != 1000 || observations[0].transactionHash != "0xtx1" {
		t.Fatalf("first observation = %+v, want ts=1000 tx=0xtx1", observations[0])
	}
	if observations[1].observationTimestamp != 1260 || observations[1].transactionHash != "0xtx2" {
		t.Fatalf("deduped observation = %+v, want ts=1260 tx=0xtx2 (earliest block)", observations[1])
	}
	if observations[2].observationTimestamp != 1500 {
		t.Fatalf("third observation ts = %d, want 1500", observations[2].observationTimestamp)
	}
}

func TestLoadFeedHeartbeatConfigs(t *testing.T) {
	t.Parallel()

	t.Run("valid config", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "heartbeat-config.json")
		configBody := `[
			{
				"stream_id": "1044000004",
				"feed_id": "` + testFeedID + `",
				"heartbeat": 255
			}
		]`
		if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		configs, err := loadFeedHeartbeatConfigs(configPath)
		if err != nil {
			t.Fatalf("loadFeedHeartbeatConfigs() error: %v", err)
		}
		if len(configs) != 1 {
			t.Fatalf("got %d configs, want 1", len(configs))
		}
		if configs[0].FeedID != testFeedID || configs[0].Heartbeat != 255 {
			t.Fatalf("config = %+v, unexpected values", configs[0])
		}
	})

	t.Run("empty config array", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "empty.json")
		if err := os.WriteFile(configPath, []byte("[]"), 0o644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		_, err := loadFeedHeartbeatConfigs(configPath)
		if err == nil {
			t.Fatal("expected error for empty config array")
		}
	})

	t.Run("invalid heartbeat", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "bad-heartbeat.json")
		configBody := `[{"feed_id":"` + testFeedID + `","heartbeat":0}]`
		if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		_, err := loadFeedHeartbeatConfigs(configPath)
		if err == nil {
			t.Fatal("expected error for non-positive heartbeat")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(configPath, []byte("{"), 0o644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		_, err := loadFeedHeartbeatConfigs(configPath)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadFeedHeartbeatConfigs(filepath.Join(t.TempDir(), "missing.json"))
		if err == nil {
			t.Fatal("expected error for missing config file")
		}
	})
}

func TestReadObservationsByFeedErrors(t *testing.T) {
	t.Parallel()

	t.Run("wrong csv format", func(t *testing.T) {
		// get-feed-gaps CSV starts with feed_id; get-feed-updated-events starts with success.
		path := filepath.Join(t.TempDir(), "gaps.csv")
		content := "feed_id,observation_time_utc,observation_timestamp,gap_since_last_update_s\n"
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile() error: %v", err)
		}

		_, err := readObservationsByFeed(path, map[string]struct{}{testFeedID: {}})
		if err == nil {
			t.Fatal("expected error for feed-gaps CSV format")
		}
		if !strings.Contains(err.Error(), `unexpected header "feed_id"`) {
			t.Fatalf("error = %q, want header mismatch on feed_id", err)
		}
		if !strings.Contains(err.Error(), `expected "success"`) {
			t.Fatalf("error = %q, want hint to use get-feed-updated-events CSV", err)
		}
	})

	t.Run("unsorted csv still produces ordered observations", func(t *testing.T) {
		csvPath := writeTestEventsCSV(t, [][]string{
			{"true", "executed successfully", "0xtx3", "100", "1740000003000000", "1500", testFeedID, "102"},
			{"true", "executed successfully", "0xtx1", "100", "1740000000000000", "1000", testFeedID, "100"},
			{"true", "executed successfully", "0xtx2", "100", "1740000001000000", "1260", testFeedID, "101"},
		})

		observationsByFeed, err := readObservationsByFeed(csvPath, map[string]struct{}{testFeedID: {}})
		if err != nil {
			t.Fatalf("readObservationsByFeed() error: %v", err)
		}

		observations := observationsByFeed[testFeedID]
		if len(observations) != 3 {
			t.Fatalf("got %d observations, want 3", len(observations))
		}
		for i := 1; i < len(observations); i++ {
			if observations[i].observationTimestamp <= observations[i-1].observationTimestamp {
				t.Fatalf("observations not sorted: %+v", observations)
			}
		}
	})

	t.Run("configured feed missing from csv yields empty observations", func(t *testing.T) {
		csvPath := writeTestEventsCSV(t, [][]string{
			{"true", "executed successfully", "0xtx1", "100", "1740000000000000", "1000", testFeedID, "100"},
		})

		missingFeed := "0xdeadbeef000000000000000000000000000000000000000000000000000000"
		observationsByFeed, err := readObservationsByFeed(csvPath, map[string]struct{}{missingFeed: {}})
		if err != nil {
			t.Fatalf("readObservationsByFeed() error: %v", err)
		}
		if len(observationsByFeed[missingFeed]) != 0 {
			t.Fatalf("expected no observations for missing feed, got %+v", observationsByFeed[missingFeed])
		}
	})
}

func TestRunCheckHeartbeatMissesMixedFeeds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "events.csv")

	csvBody := "success,vm_status,transaction_hash,gas_used,block_timestamp,observation_timestamp,feed_id,benchmark\n" +
		"true,executed successfully,0xtx1,100,1740000000000000,1000," + testFeedID + ",100\n" +
		"true,executed successfully,0xtx2,100,1740000001000000,1260," + testFeedID + ",101\n"
	if err := os.WriteFile(csvPath, []byte(csvBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configs := []FeedHeartbeatConfig{
		{StreamID: "1044000004", FeedID: testFeedID, Heartbeat: 255},
		{StreamID: "9999999999", FeedID: "0xdeadbeef000000000000000000000000000000000000000000000000000000", Heartbeat: 255},
	}

	if err := runCheckHeartbeatMisses(csvPath, configs); err != nil {
		t.Fatalf("runCheckHeartbeatMisses() error: %v", err)
	}
}

func TestFindHeartbeatBreachesLongHeartbeat(t *testing.T) {
	t.Parallel()

	// Some feeds (e.g. 1040000002) use ~24h heartbeats; large gaps should still be OK.
	feedConfig := FeedHeartbeatConfig{
		StreamID:  "1040000002",
		FeedID:    testFeedID,
		Heartbeat: 86355,
	}
	observations := []heartbeatObservation{
		{observationTimestamp: 1000, transactionHash: "0x1"},
		{observationTimestamp: 20000, transactionHash: "0x2"},
	}

	breaches, summary := findHeartbeatBreaches(feedConfig, observations)
	if len(breaches) != 0 {
		t.Fatalf("expected no breach for long heartbeat, got %d", len(breaches))
	}
	if summary.Status != "OK" || summary.MaxGapSeconds != 19000 {
		t.Fatalf("summary = %+v, want OK with max gap 19000", summary)
	}
}

func TestRunCheckHeartbeatMisses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	csvPath := filepath.Join(dir, "events.csv")
	configPath := filepath.Join(dir, "config.json")

	csvBody := "success,vm_status,transaction_hash,gas_used,block_timestamp,observation_timestamp,feed_id,benchmark\n" +
		"true,executed successfully,0xtx1,100,1740000000000000,1000," + testFeedID + ",100\n" +
		"true,executed successfully,0xtx2,100,1740000001000000,1260," + testFeedID + ",101\n" +
		"true,executed successfully,0xtx3,100,1740000002000000,1500," + testFeedID + ",102\n"
	if err := os.WriteFile(csvPath, []byte(csvBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configBody := `[{"stream_id":"1044000004","feed_id":"` + testFeedID + `","heartbeat":255}]`
	if err := os.WriteFile(configPath, []byte(configBody), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	configs, err := loadFeedHeartbeatConfigs(configPath)
	if err != nil {
		t.Fatalf("loadFeedHeartbeatConfigs() error: %v", err)
	}

	if err := runCheckHeartbeatMisses(csvPath, configs); err != nil {
		t.Fatalf("runCheckHeartbeatMisses() error: %v", err)
	}
}

func writeTestEventsCSV(t *testing.T, rows [][]string) string {
	t.Helper()

	// Minimal get-feed-updated-events CSV for unit tests.
	path := filepath.Join(t.TempDir(), "events.csv")
	var content strings.Builder
	content.WriteString("success,vm_status,transaction_hash,gas_used,block_timestamp,observation_timestamp,feed_id,benchmark\n")
	for _, row := range rows {
		for i, field := range row {
			if i > 0 {
				content.WriteString(",")
			}
			content.WriteString(field)
		}
		content.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(content.String()), 0o644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	return path
}
