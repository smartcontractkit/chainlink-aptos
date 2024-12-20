package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type FeedUpdatedEventData struct {
	TransactionSuccess   bool
	TransationVMStatus   string
	TransactionHash      string
	TransactionGasUsed   string
	BlockTimestamp       string
	ObservationTimestamp string
	FeedId               string
	Benchmark            string
}

type TransactionQueryOptions struct {
	IncludeOnlyMostRecent bool
}

func BuildMGetFeedUpdatedEvents() *cobra.Command {
	var (
		environmentStr        string
		includeOnlyMostRecent bool
	)

	cmd := cobra.Command{
		Use:   "get-feed-updated-events",
		Short: "Get FeedUpdated events",
		RunE: func(cmd *cobra.Command, args []string) error {
			transactionQueryOptions := TransactionQueryOptions{
				IncludeOnlyMostRecent: includeOnlyMostRecent,
			}
			runGetFeedUpdatedEvents(environmentStr, transactionQueryOptions)
			return nil
		},
	}

	cmd.Flags().StringVarP(&environmentStr, "environment", "e", "staging", "Environment")
	cmd.Flags().BoolVarP(&includeOnlyMostRecent, "includeOnlyMostRecent", "l", false, "Include only most recent transactions")

	cmd.MarkFlagRequired("environment")

	return &cmd
}

func runGetFeedUpdatedEvents(env string, transactionQueryOptions TransactionQueryOptions) {
	accounts := GetAccountsByEnvironment(env)
	feedsData := getFeedUpdatedEventsFromAccounts(accounts, env, transactionQueryOptions)

	outputFile := fmt.Sprintf("aptos-data-feed-events-%s-%d.csv", env, time.Now().UnixMilli())
	if err := writeToCSV(outputFile, feedUpdatedEventDataArrayToRawStringArray(feedsData)); err != nil {
		log.Fatalf("error while writing %s: %v", outputFile, err)
	}

	// Create a "latest" version of the file to compose scripts easier
	outputLatestFile := fmt.Sprintf("aptos-data-feed-events-%s-latest.csv", env)
	cmd := exec.Command("cp", outputFile, outputLatestFile)

	if err := cmd.Run(); err != nil {
		log.Fatalf("failed to copy file using cp: %s: %v", outputLatestFile, err)
	}

	// Check the last transmission time
	printWhenLatestTransmissionHappened(feedsData)
}

func printWhenLatestTransmissionHappened(feedsData []FeedUpdatedEventData) {
	latestEvent, timestamp := findLatestEvent(feedsData)
	latestBlocktimeTime := time.Unix(timestamp/1000000, timestamp/1000000000)
	currentTime := time.Now()
	diffSeconds := int64(currentTime.Sub(latestBlocktimeTime).Seconds())

	log.Printf("Latest transmission happened %d seconds ago with hash %s", diffSeconds, latestEvent.TransactionHash)
}

func findLatestEvent(events []FeedUpdatedEventData) (FeedUpdatedEventData, int64) {
	var latestEvent FeedUpdatedEventData
	var maxTimestamp int64

	for _, event := range events {
		blockTimestamp, err := strconv.ParseInt(event.BlockTimestamp, 10, 64)
		if err != nil {
			log.Println("Error parsing block_timestamp: %w", err)
			continue
		}

		if blockTimestamp > maxTimestamp {
			maxTimestamp = blockTimestamp
			latestEvent = event
		}
	}

	return latestEvent, maxTimestamp
}

func getFeedUpdatedEventsFromAccounts(accounts []string, environment string, transactionQueryOptions TransactionQueryOptions) []FeedUpdatedEventData {
	log.Printf("fetching feed update events from environment %s\n", environment)

	var allFeedUpdateEvents []FeedUpdatedEventData

	for _, account := range accounts {

		feedUpdateEvents, err := fetchFeedUpdatedEventsFromAccountTransactions(account, environment, transactionQueryOptions)
		if err != nil {
			// I guess we could avoid fatal and just get whatever was possible
			log.Fatalf("failed get feed update events from account: %v", err)
		}

		allFeedUpdateEvents = append(allFeedUpdateEvents, feedUpdateEvents...)
	}

	log.Printf("got %d feed update events\n", len(allFeedUpdateEvents))

	return allFeedUpdateEvents
}

func fetchFeedUpdatedEventsFromAccountTransactions(account string, environment string, transactionQueryOptions TransactionQueryOptions) ([]FeedUpdatedEventData, error) {
	transactions, err := fetchTransactionsFromAccount(account, environment, transactionQueryOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch feed update events from account: %w", err)
	}

	var records []FeedUpdatedEventData

	for _, tx := range transactions {
		for _, event := range tx.Events {
			if strings.HasSuffix(event.Type, "::registry::FeedUpdated") {
				record := FeedUpdatedEventData{
					TransactionSuccess:   tx.Success,
					TransationVMStatus:   tx.VMStatus,
					TransactionHash:      tx.Hash,
					TransactionGasUsed:   tx.GasUsed,
					BlockTimestamp:       tx.Timestamp,
					ObservationTimestamp: toString(event.Data["timestamp"]),
					FeedId:               toString(event.Data["feed_id"]),
					Benchmark:            toString(event.Data["benchmark"]),
				}
				records = append(records, record)
			}
		}
	}

	return records, nil
}

func fetchTransactionsFromAccount(account, environment string, transactionQueryOptions TransactionQueryOptions) ([]Transaction, error) {
	log.Printf("Fetching transactions from account %s in environment %s with options %+v\n", account, environment, transactionQueryOptions)

	var allTransactions []Transaction
	var fetchFunc func(string, string) ([]Transaction, error)

	if transactionQueryOptions.IncludeOnlyMostRecent {
		fetchFunc = fetchMostRecentTransactionsFromAccountt
	} else {
		fetchFunc = fetchAllTransactionsFromAccount
	}

	allTransactions, err := fetchFunc(account, environment)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch paginated transactions: %w", err)
	}

	log.Printf("Finished fetching transactions from account %s. Total transactions: %d\n", account, len(allTransactions))
	return allTransactions, nil
}

func feedUpdatedEventDataArrayToRawStringArray(feedUpdatedEvents []FeedUpdatedEventData) [][]string {
	var records [][]string

	for _, feedUpdatedEvent := range feedUpdatedEvents {
		row := []string{
			strconv.FormatBool(feedUpdatedEvent.TransactionSuccess),
			feedUpdatedEvent.TransationVMStatus,
			feedUpdatedEvent.TransactionHash,
			feedUpdatedEvent.TransactionGasUsed,
			feedUpdatedEvent.BlockTimestamp,
			feedUpdatedEvent.ObservationTimestamp,
			feedUpdatedEvent.FeedId,
			feedUpdatedEvent.Benchmark,
		}

		records = append(records, row)
	}

	return records
}

func toString(value interface{}) string {
	if value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}

func writeToCSV(outputFile string, records [][]string) error {
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	headers := []string{"success", "vm_status", "transaction_hash", "gas_used", "block_timestamp", "observation_timestamp", "feed_id", "benchmark"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write hearder in file: %w", err)
	}

	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write row in CSV: %w", err)
		}
	}

	return nil
}
