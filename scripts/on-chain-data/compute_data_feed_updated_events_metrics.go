package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/montanaflynn/stats"
	"github.com/spf13/cobra"
)

type FeedUpdateEventInputData struct {
	TransactionHash      string
	TransactionGasUsed   int64
	BlockTimestamp       int64
	ObservationTimestamp int64
	FeedId               string
	TransmissionLatency  float64
}

type Stats struct {
	Avg float64
	Min float64
	Max float64
	P90 float64
	P95 float64
	P99 float64
}

type SLA struct {
	Sla30 float64
	Sla45 float64
	Sla60 float64
}

func readCSVFile(input string, expectedHeaders []string) ([][]string, error) {
	file, err := os.Open(input)
	if err != nil {
		return nil, fmt.Errorf("error while loading file: %s, %w", input, err)
	}
	defer file.Close()

	// Create a CSV reader
	reader := csv.NewReader(file)

	// Read the header
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error while reading header from file: %s, %w", input, err)
	}

	// Ensure correct header names
	for i, headerName := range expectedHeaders {
		if strings.ToLower(header[i]) != headerName {
			return nil, fmt.Errorf("unexpected header %s formate: %w", header[i], err)
		}
	}

	// Read all records
	var records [][]string

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		records = append(records, record)
	}

	return records, nil
}

func readFeedUpdateEvents(input string, timeframeInSeconds int64) ([]FeedUpdateEventInputData, error) {
	expectedHeaders := []string{"success", "vm_status", "transaction_hash", "gas_used", "block_timestamp", "observation_timestamp", "feed_id", "benchmark"}

	records, err := readCSVFile(input, expectedHeaders)
	if err != nil {
		return nil, fmt.Errorf("unexpected error while reading CSV: %w", err)
	}

	var events []FeedUpdateEventInputData
	for _, record := range records {
		gasUsed, err := strconv.ParseInt(record[3], 10, 64)
		if err != nil {
			fmt.Println("Error parsing gas_used", err)
			continue
		}

		blockTimestamp, err := strconv.ParseInt(record[4], 10, 64)
		if err != nil {
			fmt.Println("Error parsing block_timestamp:", err)
			continue
		}

		observationTimestamp, err := strconv.ParseInt(record[5], 10, 64)
		if err != nil {
			fmt.Println("Error parsing observation_timestamp:", err)
			continue
		}

		transactionHash := record[2]
		feedId := record[6]

		// Calculate transmission_latency
		transmissionLatency := (float64(blockTimestamp) / 1000000) - float64(observationTimestamp)

		// Only includes events in the expected timeframe
		blockTimestampTime := time.Unix(blockTimestamp/1000000, blockTimestamp/1000000000)
		currentTime := time.Now()
		diffSeconds := int64(currentTime.Sub(blockTimestampTime).Seconds())

		if timeframeInSeconds <= 0 || diffSeconds <= timeframeInSeconds {
			events = append(events, FeedUpdateEventInputData{
				TransactionHash:      transactionHash,
				TransactionGasUsed:   gasUsed,
				BlockTimestamp:       blockTimestamp,
				ObservationTimestamp: observationTimestamp,
				FeedId:               feedId,
				TransmissionLatency:  transmissionLatency,
			})
		}
	}

	return events, nil
}

func getLatencies(events []FeedUpdateEventInputData) []float64 {
	var latencies []float64

	for _, event := range events {
		latencies = append(latencies, event.TransmissionLatency)
	}

	return latencies
}

func getLatencyStatsWithSLA(events []FeedUpdateEventInputData) (Stats, SLA) {
	latencies := getLatencies(events)

	return calculateStats(latencies), calculateSLA(latencies)

}

func getLatencyStatsByFeed(events []FeedUpdateEventInputData) (map[string]Stats, map[string]SLA) {
	latenciesdByFeed := make(map[string][]float64)

	for _, event := range events {
		latenciesdByFeed[event.FeedId] = append(latenciesdByFeed[event.FeedId], event.TransmissionLatency)
	}

	latencyStatsByFeed := make(map[string]Stats)
	for feedId, latencies := range latenciesdByFeed {
		latencyStatsByFeed[feedId] = calculateStats(latencies)
	}

	slasByFeed := make(map[string]SLA)
	for feedId, latencies := range latenciesdByFeed {
		slasByFeed[feedId] = calculateSLA(latencies)
	}

	return latencyStatsByFeed, slasByFeed
}

func getGas(events []FeedUpdateEventInputData) []float64 {
	var gas []float64

	for _, event := range events {
		gas = append(gas, float64(event.TransactionGasUsed))
	}

	return gas
}

func getGasStats(events []FeedUpdateEventInputData) Stats {
	return calculateStats(getGas(events))
}

func getSlowTransmissions(events []FeedUpdateEventInputData) []FeedUpdateEventInputData {
	// Sort by TransmissionLatency desc
	sort.Slice(events, func(i, j int) bool {
		return events[i].TransmissionLatency > events[j].TransmissionLatency
	})

	slowTransactions := make([]FeedUpdateEventInputData, 0, 10)
	for i := 0; i < len(events) && i < 10; i++ {
		slowTransactions = append(slowTransactions, events[i])
	}

	return slowTransactions
}

func printStats(title string, theStats Stats) {
	log.Println(title)
	log.Printf("  Avg: %.2f\n", theStats.Avg)
	log.Printf("  Min: %.2f\n", theStats.Min)
	log.Printf("  Max: %.2f\n", theStats.Max)
	log.Printf("  P90: %.2f\n", theStats.P90)
	log.Printf("  P95: %.2f\n", theStats.P95)
	log.Printf("  P99: %.2f\n", theStats.P99)
}

func printStatsWithSLA(title string, theStats Stats, slas SLA) {
	printStats(title, theStats)
	log.Printf("  SLA 30: %.2f\n", slas.Sla30)
	log.Printf("  SLA 45: %.2f\n", slas.Sla45)
	log.Printf("  SLA 60: %.2f\n", slas.Sla60)
}

func printEvents(title string, events []FeedUpdateEventInputData) {
	log.Println(title)

	for index, event := range events {
		log.Printf("event #%d transaction_hash: %s\n", index, event.TransactionHash)
		log.Printf("  feed_id: %s\n", event.FeedId)
		log.Printf("  latency: %.2f\n", event.TransmissionLatency)
	}
}

func printDataFeedEventStats(input string, timeframeInSeconds int64) {
	events, err := readFeedUpdateEvents(input, timeframeInSeconds)
	if err != nil {
		log.Fatalf("error reading events %v", err)
		return
	}

	if timeframeInSeconds <= 0 {
		log.Printf("Processing all events from file #%s, including %d events\n", input, len(events))
	} else {
		log.Printf("Processing events from file #%s in a timeframe of the last %d seconds, including %d events\n", input, timeframeInSeconds, len(events))
	}

	if len(events) == 0 {
		log.Printf("no transmissions found")
		return
	}

	// Gas stats
	gasStats := getGasStats(events)
	printStats("Gas stats:", gasStats)

	// Latency stats and SLA
	latencyStats, sla := getLatencyStatsWithSLA(events)
	printStatsWithSLA("Latency stats:", latencyStats, sla)

	latencyStatsByFeed, slasByFeed := getLatencyStatsByFeed(events)
	for feedId, _ := range latencyStatsByFeed {
		printStatsWithSLA(fmt.Sprintf("latency stats by feed %s:", feedId), latencyStatsByFeed[feedId], slasByFeed[feedId])
	}

	// Top 10 slow transactions:
	slowTransmissions := getSlowTransmissions(events)
	printEvents("Slow transmissions", slowTransmissions)
}

func BuildComputeDataFeedUpdatedEventsMetrics() *cobra.Command {
	var (
		inputFile          string
		timeframeInSeconds int64
	)

	cmd := cobra.Command{
		Use:   "compute-data-feed-updated-events-metrics",
		Short: "Compute DataFeedUpdated events metrics",
		RunE: func(cmd *cobra.Command, args []string) error {
			printDataFeedEventStats(inputFile, timeframeInSeconds)
			return nil
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file")
	cmd.Flags().Int64VarP(&timeframeInSeconds, "timeframe", "t", -1, "Timeframe of events expressed in seconds. It will only include the transactions/events that happened in the last N seconds.")
	cmd.MarkFlagRequired("inputFile")

	return &cmd
}

func calculateStats(values []float64) Stats {
	avg, _ := stats.Median(values)
	min, _ := stats.Min(values)
	max, _ := stats.Max(values)
	p90, _ := stats.Percentile(values, 90)
	p95, _ := stats.Percentile(values, 95)
	p99, _ := stats.Percentile(values, 99)

	return Stats{
		Avg: avg,
		Min: min,
		Max: max,
		P90: p90,
		P95: p95,
		P99: p99,
	}
}

func calculateSLA(values []float64) SLA {
	sla30Count := 0
	sla45Count := 0
	sla60Count := 0

	for _, value := range values {
		if value <= 30 {
			sla30Count++
		}
		if value <= 45 {
			sla45Count++
		}
		if value <= 60 {
			sla60Count++
		}
	}

	sla30 := (float64(sla30Count) / float64(len(values))) * 100
	sla45 := (float64(sla45Count) / float64(len(values))) * 100
	sla60 := (float64(sla60Count) / float64(len(values))) * 100

	return SLA{
		Sla30: sla30,
		Sla45: sla45,
		Sla60: sla60,
	}
}
