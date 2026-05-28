// check-heartbeat-misses scans a get-feed-updated-events CSV for provable heartbeat
// breaches. For each configured feed, consecutive observation timestamps are compared;
// a breach is recorded when gap > heartbeat. No wall-clock time is used.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type FeedHeartbeatConfig struct {
	StreamID  string `json:"stream_id"`
	FeedID    string `json:"feed_id"`
	Heartbeat int64  `json:"heartbeat"`
}

type heartbeatObservation struct {
	observationTimestamp int64
	blockTimestamp       int64
	transactionHash      string
}

type heartbeatBreach struct {
	StreamID             string
	FeedID               string
	Heartbeat            int64
	GapSeconds           int64
	PreviousObsTimestamp int64
	CurrentObsTimestamp  int64
	TransactionHash      string
}

type feedHeartbeatSummary struct {
	StreamID      string
	FeedID        string
	Heartbeat     int64
	UpdateCount   int
	GapCount      int
	BreachCount   int
	MaxGapSeconds int64
	Status        string
}

func BuildCheckHeartbeatMisses() *cobra.Command {
	var (
		inputFile  string
		configFile string
	)

	cmd := cobra.Command{
		Use:   "check-heartbeat-misses",
		Short: "Find heartbeat breaches in a FeedUpdated events CSV by comparing observation gaps to configured thresholds",
		RunE: func(cmd *cobra.Command, args []string) error {
			feedConfigs, err := loadFeedHeartbeatConfigs(configFile)
			if err != nil {
				return err
			}

			return runCheckHeartbeatMisses(inputFile, feedConfigs)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "FeedUpdated events CSV from get-feed-updated-events")
	cmd.Flags().StringVarP(&configFile, "config", "c", "", "JSON file with stream_id, feed_id, and heartbeat (seconds) per feed")

	cmd.MarkFlagRequired("input")
	cmd.MarkFlagRequired("config")

	return &cmd
}

func loadFeedHeartbeatConfigs(configFile string) ([]FeedHeartbeatConfig, error) {
	body, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configFile, err)
	}

	var feedConfigs []FeedHeartbeatConfig
	if err := json.Unmarshal(body, &feedConfigs); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configFile, err)
	}

	if len(feedConfigs) == 0 {
		return nil, fmt.Errorf("no feed heartbeat configuration found in %s", configFile)
	}

	for i := range feedConfigs {
		feedConfigs[i].FeedID = normalizeFeedID(feedConfigs[i].FeedID)
		if feedConfigs[i].Heartbeat <= 0 {
			return nil, fmt.Errorf("heartbeat must be positive for feed %s", feedConfigs[i].FeedID)
		}
	}

	return feedConfigs, nil
}

func normalizeFeedID(feedID string) string {
	feedID = strings.TrimSpace(feedID)
	if !strings.HasPrefix(feedID, "0x") {
		feedID = "0x" + feedID
	}
	return strings.ToLower(feedID)
}

func readObservationsByFeed(input string, feedIDs map[string]struct{}) (map[string][]heartbeatObservation, error) {
	// Requires get-feed-updated-events CSV columns, not get-feed-gaps output.
	expectedHeaders := []string{"success", "vm_status", "transaction_hash", "gas_used", "block_timestamp", "observation_timestamp", "feed_id", "benchmark"}

	records, err := readCSVFile(input, expectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("failed to read CSV (expected output from get-feed-updated-events): %w", err)
	}

	dedupedByFeed := make(map[string]map[int64]heartbeatObservation)

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

		if _, ok := dedupedByFeed[feedID]; !ok {
			dedupedByFeed[feedID] = make(map[int64]heartbeatObservation)
		}

		current, exists := dedupedByFeed[feedID][observationTimestamp]
		// One writer tx batch can emit duplicate rows for the same observation; keep the earliest block.
		if !exists || blockTimestamp < current.blockTimestamp {
			dedupedByFeed[feedID][observationTimestamp] = heartbeatObservation{
				observationTimestamp: observationTimestamp,
				blockTimestamp:       blockTimestamp,
				transactionHash:      record[2],
			}
		}
	}

	observationsByFeed := make(map[string][]heartbeatObservation, len(dedupedByFeed))
	for feedID, byTimestamp := range dedupedByFeed {
		observations := make([]heartbeatObservation, 0, len(byTimestamp))
		for _, observation := range byTimestamp {
			observations = append(observations, observation)
		}

		sort.Slice(observations, func(i, j int) bool {
			return observations[i].observationTimestamp < observations[j].observationTimestamp
		})

		observationsByFeed[feedID] = observations
	}

	return observationsByFeed, nil
}

func findHeartbeatBreaches(feedConfig FeedHeartbeatConfig, observations []heartbeatObservation) ([]heartbeatBreach, feedHeartbeatSummary) {
	// observations must already be sorted by observation_timestamp ascending.
	summary := feedHeartbeatSummary{
		StreamID:  feedConfig.StreamID,
		FeedID:    feedConfig.FeedID,
		Heartbeat: feedConfig.Heartbeat,
		Status:    "NO_DATA",
	}

	if len(observations) == 0 {
		return nil, summary
	}

	summary.UpdateCount = len(observations)
	summary.Status = "OK"

	var breaches []heartbeatBreach
	var lastObservationTimestamp int64
	hasLastObservation := false

	for _, observation := range observations {
		if hasLastObservation {
			gapSeconds := observation.observationTimestamp - lastObservationTimestamp
			summary.GapCount++

			if gapSeconds > summary.MaxGapSeconds {
				summary.MaxGapSeconds = gapSeconds
			}

			if gapSeconds > feedConfig.Heartbeat {
				// Strict greater-than: gap == heartbeat is not a breach.
				summary.BreachCount++
				summary.Status = "BREACHED"
				breaches = append(breaches, heartbeatBreach{
					StreamID:             feedConfig.StreamID,
					FeedID:               feedConfig.FeedID,
					Heartbeat:            feedConfig.Heartbeat,
					GapSeconds:           gapSeconds,
					PreviousObsTimestamp: lastObservationTimestamp,
					CurrentObsTimestamp:  observation.observationTimestamp,
					TransactionHash:      observation.transactionHash,
				})
			}
		}

		lastObservationTimestamp = observation.observationTimestamp
		hasLastObservation = true
	}

	return breaches, summary
}

func runCheckHeartbeatMisses(inputFile string, feedConfigs []FeedHeartbeatConfig) error {
	feedIDs := make(map[string]struct{}, len(feedConfigs))
	for _, feedConfig := range feedConfigs {
		feedIDs[feedConfig.FeedID] = struct{}{}
	}

	observationsByFeed, err := readObservationsByFeed(inputFile, feedIDs)
	if err != nil {
		return err
	}

	var allBreaches []heartbeatBreach
	summaries := make([]feedHeartbeatSummary, 0, len(feedConfigs))

	for _, feedConfig := range feedConfigs {
		breaches, summary := findHeartbeatBreaches(feedConfig, observationsByFeed[feedConfig.FeedID])
		allBreaches = append(allBreaches, breaches...)
		summaries = append(summaries, summary)
	}

	sort.Slice(summaries, func(i, j int) bool {
		if summaries[i].StreamID != "" && summaries[j].StreamID != "" {
			return summaries[i].StreamID < summaries[j].StreamID
		}
		return summaries[i].FeedID < summaries[j].FeedID
	})

	sort.Slice(allBreaches, func(i, j int) bool {
		if allBreaches[i].GapSeconds != allBreaches[j].GapSeconds {
			return allBreaches[i].GapSeconds > allBreaches[j].GapSeconds
		}
		if allBreaches[i].FeedID != allBreaches[j].FeedID {
			return allBreaches[i].FeedID < allBreaches[j].FeedID
		}
		return allBreaches[i].CurrentObsTimestamp > allBreaches[j].CurrentObsTimestamp
	})

	printHeartbeatCheckResults(inputFile, summaries, allBreaches)

	okCount := 0
	breachFeedCount := 0
	noDataCount := 0
	totalBreaches := 0

	for _, summary := range summaries {
		totalBreaches += summary.BreachCount
		switch summary.Status {
		case "BREACHED":
			breachFeedCount++
		case "NO_DATA":
			noDataCount++
		case "OK":
			okCount++
		}
	}

	log.Printf("Summary: %d feeds OK, %d feeds with breaches, %d feeds NO_DATA, %d total breach events",
		okCount, breachFeedCount, noDataCount, totalBreaches)

	return nil
}

func printHeartbeatCheckResults(inputFile string, summaries []feedHeartbeatSummary, breaches []heartbeatBreach) {
	log.Printf("Checking heartbeat breaches in %s", inputFile)
	log.Printf("A breach is recorded when the gap between consecutive observation timestamps exceeds the configured heartbeat.")
	log.Println("")
	log.Printf("%-12s %-68s %10s %8s %8s %8s %10s %-10s",
		"Stream", "Feed ID", "Heartbeat", "Updates", "Gaps", "Breaches", "Max Gap", "Status")

	for _, summary := range summaries {
		streamID := summary.StreamID
		if streamID == "" {
			streamID = "-"
		}

		maxGap := "-"
		if summary.GapCount > 0 {
			maxGap = fmt.Sprintf("%ds", summary.MaxGapSeconds)
		}

		log.Printf("%-12s %-68s %10d %8d %8d %8d %10s %-10s",
			streamID,
			summary.FeedID,
			summary.Heartbeat,
			summary.UpdateCount,
			summary.GapCount,
			summary.BreachCount,
			maxGap,
			summary.Status,
		)
	}

	if len(breaches) == 0 {
		log.Println("")
		log.Println("No heartbeat breaches found in CSV.")
		return
	}

	const topBreachLimit = 20
	topBreaches := breaches
	if len(topBreaches) > topBreachLimit {
		topBreaches = topBreaches[:topBreachLimit]
	}

	log.Println("")
	log.Printf("Heartbeat breaches (top %d, %d total):", len(topBreaches), len(breaches))
	for _, breach := range topBreaches {
		streamID := breach.StreamID
		if streamID == "" {
			streamID = "-"
		}

		log.Printf("  stream %s | feed %s | gap %ds (HB %ds, over by %ds) | %s -> %s UTC | tx %s",
			streamID,
			breach.FeedID,
			breach.GapSeconds,
			breach.Heartbeat,
			breach.GapSeconds-breach.Heartbeat,
			formatUnixSecondsUTC(breach.PreviousObsTimestamp),
			formatUnixSecondsUTC(breach.CurrentObsTimestamp),
			breach.TransactionHash,
		)
	}
}
