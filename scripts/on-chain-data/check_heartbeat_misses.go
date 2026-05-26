package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type FeedHeartbeatConfig struct {
	StreamID  string `json:"stream_id"`
	FeedID    string `json:"feed_id"`
	Heartbeat int64  `json:"heartbeat"`
}

type LatestFeedObservation struct {
	StreamID             string
	FeedID               string
	Heartbeat            int64
	ObservationTimestamp int64
	BlockTimestamp       int64
	TransactionHash      string
}

type HeartbeatCheckResult struct {
	StreamID             string
	FeedID               string
	Heartbeat            int64
	ObservationTimestamp int64
	AgeSeconds           int64
	Status               string
	TransactionHash      string
}

func BuildCheckHeartbeatMisses() *cobra.Command {
	var (
		inputFile  string
		configFile string
		feedFlags  []string
	)

	cmd := cobra.Command{
		Use:   "check-heartbeat-misses",
		Short: "Check configured feeds for heartbeat misses using FeedUpdated event CSV data",
		RunE: func(cmd *cobra.Command, args []string) error {
			feedConfigs, err := loadFeedHeartbeatConfigs(configFile, feedFlags)
			if err != nil {
				return err
			}

			return runCheckHeartbeatMisses(inputFile, feedConfigs)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "FeedUpdated events CSV from get-feed-updated-events")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "JSON file listing feed_id, optional stream_id, and heartbeat seconds")
	cmd.Flags().StringArrayVar(&feedFlags, "feed", nil, "Feed heartbeat override in feed_id:heartbeat form (repeatable)")

	cmd.MarkFlagRequired("input")

	return &cmd
}

func loadFeedHeartbeatConfigs(configFile string, feedFlags []string) ([]FeedHeartbeatConfig, error) {
	if configFile == "" && len(feedFlags) == 0 {
		return nil, fmt.Errorf("provide at least one of --config or --feed")
	}

	feedConfigs := make([]FeedHeartbeatConfig, 0)

	if configFile != "" {
		body, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
		}

		if err := json.Unmarshal(body, &feedConfigs); err != nil {
			return nil, fmt.Errorf("failed to parse config file %s: %w", configFile, err)
		}
	}

	for _, feedFlag := range feedFlags {
		feedConfig, err := parseFeedHeartbeatFlag(feedFlag)
		if err != nil {
			return nil, err
		}
		feedConfigs = append(feedConfigs, feedConfig)
	}

	if len(feedConfigs) == 0 {
		return nil, fmt.Errorf("no feed heartbeat configuration found")
	}

	for i := range feedConfigs {
		feedConfigs[i].FeedID = normalizeFeedID(feedConfigs[i].FeedID)
		if feedConfigs[i].Heartbeat <= 0 {
			return nil, fmt.Errorf("heartbeat must be positive for feed %s", feedConfigs[i].FeedID)
		}
	}

	return feedConfigs, nil
}

func parseFeedHeartbeatFlag(feedFlag string) (FeedHeartbeatConfig, error) {
	parts := strings.Split(feedFlag, ":")
	if len(parts) != 2 {
		return FeedHeartbeatConfig{}, fmt.Errorf("invalid --feed value %q, expected feed_id:heartbeat", feedFlag)
	}

	heartbeat, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return FeedHeartbeatConfig{}, fmt.Errorf("invalid heartbeat in --feed value %q: %w", feedFlag, err)
	}

	return FeedHeartbeatConfig{
		FeedID:    parts[0],
		Heartbeat: heartbeat,
	}, nil
}

func normalizeFeedID(feedID string) string {
	feedID = strings.TrimSpace(feedID)
	if !strings.HasPrefix(feedID, "0x") {
		feedID = "0x" + feedID
	}
	return strings.ToLower(feedID)
}

func readLatestObservationsByFeed(input string, feedIDs map[string]struct{}) (map[string]LatestFeedObservation, error) {
	expectedHeaders := []string{"success", "vm_status", "transaction_hash", "gas_used", "block_timestamp", "observation_timestamp", "feed_id", "benchmark"}

	records, err := readCSVFile(input, expectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV: %w", err)
	}

	latestByFeed := make(map[string]LatestFeedObservation)

	for _, record := range records {
		feedID := normalizeFeedID(record[6])
		if _, ok := feedIDs[feedID]; !ok {
			continue
		}

		observationTimestamp, err := strconv.ParseInt(record[5], 10, 64)
		if err != nil {
			log.Printf("warning: skipping row with invalid observation_timestamp for feed %s: %v", feedID, err)
			continue
		}

		blockTimestamp, err := strconv.ParseInt(record[4], 10, 64)
		if err != nil {
			log.Printf("warning: skipping row with invalid block_timestamp for feed %s: %v", feedID, err)
			continue
		}

		current, exists := latestByFeed[feedID]
		if !exists || observationTimestamp > current.ObservationTimestamp {
			latestByFeed[feedID] = LatestFeedObservation{
				FeedID:               feedID,
				ObservationTimestamp: observationTimestamp,
				BlockTimestamp:       blockTimestamp,
				TransactionHash:      record[2],
			}
		}
	}

	return latestByFeed, nil
}

func runCheckHeartbeatMisses(inputFile string, feedConfigs []FeedHeartbeatConfig) error {
	feedIDs := make(map[string]struct{}, len(feedConfigs))
	configByFeedID := make(map[string]FeedHeartbeatConfig, len(feedConfigs))

	for _, feedConfig := range feedConfigs {
		feedIDs[feedConfig.FeedID] = struct{}{}
		configByFeedID[feedConfig.FeedID] = feedConfig
	}

	latestByFeed, err := readLatestObservationsByFeed(inputFile, feedIDs)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	results := make([]HeartbeatCheckResult, 0, len(feedConfigs))

	for _, feedConfig := range feedConfigs {
		latest, ok := latestByFeed[feedConfig.FeedID]
		if !ok {
			results = append(results, HeartbeatCheckResult{
				StreamID: feedConfig.StreamID,
				FeedID:   feedConfig.FeedID,
				Heartbeat: feedConfig.Heartbeat,
				Status:   "NO_DATA",
			})
			continue
		}

		ageSeconds := now.Unix() - latest.ObservationTimestamp
		status := "OK"
		if ageSeconds > feedConfig.Heartbeat {
			status = "BREACHED"
		}

		results = append(results, HeartbeatCheckResult{
			StreamID:             feedConfig.StreamID,
			FeedID:               feedConfig.FeedID,
			Heartbeat:            feedConfig.Heartbeat,
			ObservationTimestamp: latest.ObservationTimestamp,
			AgeSeconds:           ageSeconds,
			Status:               status,
			TransactionHash:      latest.TransactionHash,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].StreamID != "" && results[j].StreamID != "" {
			return results[i].StreamID < results[j].StreamID
		}
		return results[i].FeedID < results[j].FeedID
	})

	printHeartbeatCheckResults(inputFile, now, results)

	breachCount := 0
	noDataCount := 0
	okCount := 0

	for _, result := range results {
		switch result.Status {
		case "BREACHED":
			breachCount++
		case "NO_DATA":
			noDataCount++
		case "OK":
			okCount++
		}
	}

	log.Printf("Summary: %d OK, %d BREACHED, %d NO_DATA", okCount, breachCount, noDataCount)

	return nil
}

func printHeartbeatCheckResults(inputFile string, now time.Time, results []HeartbeatCheckResult) {
	log.Printf("Checking heartbeat misses from file %s", inputFile)
	log.Printf("Current time (UTC): %s", now.Format(time.RFC3339))
	log.Println("")
	log.Printf("%-12s %-68s %10s %-26s %10s %-10s %s", "Stream", "Feed ID", "Heartbeat", "Last Obs (UTC)", "Age (s)", "Status", "Notes")

	for _, result := range results {
		streamID := result.StreamID
		if streamID == "" {
			streamID = "-"
		}

		switch result.Status {
		case "NO_DATA":
			log.Printf("%-12s %-68s %10d %-26s %10s %-10s %s",
				streamID,
				result.FeedID,
				result.Heartbeat,
				"NO EVENTS IN CSV",
				"-",
				result.Status,
				"extend get-feed-updated-events lookback",
			)
		case "BREACHED":
			log.Printf("%-12s %-68s %10d %-26s %10d %-10s over by %ds, tx %s",
				streamID,
				result.FeedID,
				result.Heartbeat,
				time.Unix(result.ObservationTimestamp, 0).UTC().Format(time.RFC3339),
				result.AgeSeconds,
				result.Status,
				result.AgeSeconds-result.Heartbeat,
				result.TransactionHash,
			)
		default:
			log.Printf("%-12s %-68s %10d %-26s %10d %-10s margin %ds, tx %s",
				streamID,
				result.FeedID,
				result.Heartbeat,
				time.Unix(result.ObservationTimestamp, 0).UTC().Format(time.RFC3339),
				result.AgeSeconds,
				result.Status,
				result.Heartbeat-result.AgeSeconds,
				result.TransactionHash,
			)
		}
	}
}
