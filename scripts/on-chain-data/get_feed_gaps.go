package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

type FeedGapRow struct {
	FeedID               string
	ObservationTimestamp int64
	ObservationTimeUTC   string
	GapSinceLastUpdateS  string
	BlockTimestamp       int64
	BlockTimeUTC         string
	TransactionHash      string
	Benchmark            string
	Success              bool
	GasUsed              string
}

type feedGapObservation struct {
	feedID               string
	observationTimestamp int64
	blockTimestamp       int64
	transactionHash      string
	benchmark            string
	success              bool
	gasUsed              string
}

func BuildGetFeedGaps() *cobra.Command {
	var (
		environmentStr string
		lookbackMinutes int
	)

	cmd := cobra.Command{
		Use:   "get-feed-gaps",
		Short: "Fetch on-chain feed updates and report observation gaps per feed for a time window",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGetFeedGaps(environmentStr, lookbackMinutes)
		},
	}

	cmd.Flags().StringVarP(&environmentStr, "environment", "e", "staging", "Environment")
	cmd.Flags().IntVarP(&lookbackMinutes, "minutes", "m", 0, "Lookback period in minutes")

	cmd.MarkFlagRequired("environment")
	cmd.MarkFlagRequired("minutes")

	return &cmd
}

func runGetFeedGaps(env string, lookbackMinutes int) error {
	if lookbackMinutes <= 0 {
		return fmt.Errorf("minutes must be positive")
	}

	now := time.Now().UTC()
	windowStart := now.Add(-time.Duration(lookbackMinutes) * time.Minute)
	windowStartUnix := windowStart.Unix()

	log.Printf("Fetching feed updates from environment %s for the past %d minutes\n", env, lookbackMinutes)

	accounts := GetAccountsByEnvironment(env)
	feedEvents := getFeedUpdatedEventsFromAccounts(accounts, env, TransactionQueryOptions{
		LookbackMinutes: lookbackMinutes,
	})

	rows, gapSummaries := buildFeedGapRows(feedEvents, windowStartUnix, now)
	if len(rows) == 0 {
		log.Printf("No feed updates found in the past %d minutes", lookbackMinutes)
		return nil
	}

	outputFile := fmt.Sprintf("aptos-feed-gaps-%s-%dm-%d.csv", env, lookbackMinutes, now.UnixMilli())
	if err := writeFeedGapsCSV(outputFile, rows); err != nil {
		return err
	}

	outputLatestFile := fmt.Sprintf("aptos-feed-gaps-%s-latest.csv", env)
	if err := exec.Command("cp", outputFile, outputLatestFile).Run(); err != nil {
		return fmt.Errorf("failed to copy file to %s: %w", outputLatestFile, err)
	}

	printFeedGapSummary(env, lookbackMinutes, windowStart, now, rows, gapSummaries)
	log.Printf("Wrote %d rows to %s", len(rows), outputFile)
	log.Printf("Latest copy: %s", outputLatestFile)

	return nil
}

func buildFeedGapRows(feedEvents []FeedUpdatedEventData, windowStartUnix int64, now time.Time) ([]FeedGapRow, []feedGapSummary) {
	dedupedByFeed := make(map[string]map[int64]feedGapObservation)

	for _, event := range feedEvents {
		feedID := normalizeFeedID(event.FeedId)
		observationTimestamp, err := strconv.ParseInt(event.ObservationTimestamp, 10, 64)
		if err != nil {
			log.Printf("warning: skipping row with invalid observation_timestamp for feed %s: %v", feedID, err)
			continue
		}

		blockTimestamp, err := strconv.ParseInt(event.BlockTimestamp, 10, 64)
		if err != nil {
			log.Printf("warning: skipping row with invalid block_timestamp for feed %s: %v", feedID, err)
			continue
		}

		if _, ok := dedupedByFeed[feedID]; !ok {
			dedupedByFeed[feedID] = make(map[int64]feedGapObservation)
		}

		current, exists := dedupedByFeed[feedID][observationTimestamp]
		if !exists || blockTimestamp < current.blockTimestamp {
			dedupedByFeed[feedID][observationTimestamp] = feedGapObservation{
				feedID:               feedID,
				observationTimestamp: observationTimestamp,
				blockTimestamp:       blockTimestamp,
				transactionHash:      event.TransactionHash,
				benchmark:            event.Benchmark,
				success:              event.TransactionSuccess,
				gasUsed:              event.TransactionGasUsed,
			}
		}
	}

	feedIDs := make([]string, 0, len(dedupedByFeed))
	for feedID := range dedupedByFeed {
		feedIDs = append(feedIDs, feedID)
	}
	sort.Strings(feedIDs)

	var rows []FeedGapRow
	var gapSummaries []feedGapSummary

	for _, feedID := range feedIDs {
		observations := make([]feedGapObservation, 0, len(dedupedByFeed[feedID]))
		for _, observation := range dedupedByFeed[feedID] {
			observations = append(observations, observation)
		}

		sort.Slice(observations, func(i, j int) bool {
			return observations[i].observationTimestamp < observations[j].observationTimestamp
		})

		var lastObservationTimestamp int64
		hasLastObservation := false

		for _, observation := range observations {
			gapSinceLastUpdate := ""
			var gapValue int64

			if hasLastObservation {
				gapValue = observation.observationTimestamp - lastObservationTimestamp
				gapSinceLastUpdate = strconv.FormatInt(gapValue, 10)

				if observation.observationTimestamp >= windowStartUnix {
					gapSummaries = append(gapSummaries, feedGapSummary{
						feedID:               feedID,
						gapSeconds:           gapValue,
						previousObsTimestamp: lastObservationTimestamp,
						currentObsTimestamp:  observation.observationTimestamp,
						transactionHash:      observation.transactionHash,
					})
				}
			}

			lastObservationTimestamp = observation.observationTimestamp
			hasLastObservation = true

			if observation.observationTimestamp < windowStartUnix {
				continue
			}

			rows = append(rows, FeedGapRow{
				FeedID:               feedID,
				ObservationTimestamp: observation.observationTimestamp,
				ObservationTimeUTC:   formatUnixSecondsUTC(observation.observationTimestamp),
				GapSinceLastUpdateS:  gapSinceLastUpdate,
				BlockTimestamp:       observation.blockTimestamp,
				BlockTimeUTC:         formatUnixMicrosUTC(observation.blockTimestamp),
				TransactionHash:      observation.transactionHash,
				Benchmark:            observation.benchmark,
				Success:              observation.success,
				GasUsed:              observation.gasUsed,
			})
		}
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].FeedID != rows[j].FeedID {
			return rows[i].FeedID < rows[j].FeedID
		}
		return rows[i].ObservationTimestamp < rows[j].ObservationTimestamp
	})

	sort.Slice(gapSummaries, func(i, j int) bool {
		if gapSummaries[i].gapSeconds != gapSummaries[j].gapSeconds {
			return gapSummaries[i].gapSeconds > gapSummaries[j].gapSeconds
		}
		if gapSummaries[i].feedID != gapSummaries[j].feedID {
			return gapSummaries[i].feedID < gapSummaries[j].feedID
		}
		return gapSummaries[i].currentObsTimestamp > gapSummaries[j].currentObsTimestamp
	})

	return rows, gapSummaries
}

type feedGapSummary struct {
	feedID               string
	gapSeconds           int64
	previousObsTimestamp int64
	currentObsTimestamp  int64
	transactionHash      string
}

func printFeedGapSummary(env string, lookbackMinutes int, windowStart, now time.Time, rows []FeedGapRow, gapSummaries []feedGapSummary) {
	feedCount := make(map[string]struct{})
	for _, row := range rows {
		feedCount[row.FeedID] = struct{}{}
	}

	log.Printf("Feed gap summary for %s over the past %d minutes", env, lookbackMinutes)
	log.Printf("Window: %s -> %s UTC", windowStart.Format(time.RFC3339), now.Format(time.RFC3339))
	log.Printf("Feeds: %d | Updates in window: %d | Gaps in window: %d", len(feedCount), len(rows), len(gapSummaries))
	log.Println("")

	if len(gapSummaries) == 0 {
		log.Println("No gaps found in window.")
		return
	}

	const topGapLimit = 20
	largestGaps := gapSummaries
	if len(largestGaps) > topGapLimit {
		largestGaps = largestGaps[:topGapLimit]
	}

	log.Printf("Largest gaps (top %d, full list in CSV):", len(largestGaps))
	for _, gap := range largestGaps {
		log.Printf(
			"  feed %s | gap %ds | %s -> %s UTC | tx %s",
			gap.feedID,
			gap.gapSeconds,
			formatUnixSecondsUTC(gap.previousObsTimestamp),
			formatUnixSecondsUTC(gap.currentObsTimestamp),
			gap.transactionHash,
		)
	}

	log.Println("")
	log.Println("Per-feed stats:")
	perFeedStats := summarizeFeedGaps(gapSummaries, rows)
	sort.Slice(perFeedStats, func(i, j int) bool {
		if perFeedStats[i].maxGap != perFeedStats[j].maxGap {
			return perFeedStats[i].maxGap > perFeedStats[j].maxGap
		}
		return perFeedStats[i].feedID < perFeedStats[j].feedID
	})
	for _, stat := range perFeedStats {
		log.Printf(
			"  feed %s | updates %d | gaps %d | min %ds | max %ds",
			stat.feedID,
			stat.updates,
			stat.gaps,
			stat.minGap,
			stat.maxGap,
		)
	}
}

type feedGapStats struct {
	feedID  string
	updates int
	gaps    int
	minGap  int64
	maxGap  int64
}

func summarizeFeedGaps(gapSummaries []feedGapSummary, rows []FeedGapRow) []feedGapStats {
	updatesByFeed := make(map[string]int)
	for _, row := range rows {
		updatesByFeed[row.FeedID]++
	}

	statsByFeed := make(map[string]*feedGapStats)
	for feedID, updates := range updatesByFeed {
		statsByFeed[feedID] = &feedGapStats{
			feedID:  feedID,
			updates: updates,
			minGap:  -1,
		}
	}

	for _, gap := range gapSummaries {
		stat, ok := statsByFeed[gap.feedID]
		if !ok {
			stat = &feedGapStats{feedID: gap.feedID, minGap: -1}
			statsByFeed[gap.feedID] = stat
		}

		stat.gaps++
		if stat.minGap < 0 || gap.gapSeconds < stat.minGap {
			stat.minGap = gap.gapSeconds
		}
		if gap.gapSeconds > stat.maxGap {
			stat.maxGap = gap.gapSeconds
		}
	}

	stats := make([]feedGapStats, 0, len(statsByFeed))
	for _, stat := range statsByFeed {
		if stat.minGap < 0 {
			stat.minGap = 0
		}
		stats = append(stats, *stat)
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].feedID < stats[j].feedID
	})

	return stats
}

func writeFeedGapsCSV(outputFile string, rows []FeedGapRow) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{
		"feed_id",
		"observation_time_utc",
		"observation_timestamp",
		"gap_since_last_update_s",
		"block_time_utc",
		"block_timestamp",
		"transaction_hash",
		"benchmark",
		"success",
		"gas_used",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, row := range rows {
		if err := writer.Write([]string{
			row.FeedID,
			row.ObservationTimeUTC,
			strconv.FormatInt(row.ObservationTimestamp, 10),
			row.GapSinceLastUpdateS,
			row.BlockTimeUTC,
			strconv.FormatInt(row.BlockTimestamp, 10),
			row.TransactionHash,
			row.Benchmark,
			strconv.FormatBool(row.Success),
			row.GasUsed,
		}); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

func formatUnixSecondsUTC(timestamp int64) string {
	return time.Unix(timestamp, 0).UTC().Format("2006-01-02 15:04:05")
}

func formatUnixMicrosUTC(timestampMicros int64) string {
	seconds := timestampMicros / 1_000_000
	micros := timestampMicros % 1_000_000
	return time.Unix(seconds, micros*1_000).UTC().Format("2006-01-02 15:04:05.000000")
}
