package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type ReportProcessedEvent struct {
	TransactionHash     string
	BlockTimestamp      string
	ReportId            int64
	WorkflowExecutionId string
}

func BuildFindFeedUpdateWorkflowReportId() *cobra.Command {
	var (
		environmentStr        string
		reportId              float64
		includeOnlyMostRecent bool
	)

	cmd := cobra.Command{
		Use:   "find-workflow-report-id",
		Short: "Find on-chain transaction for a given workflow report ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			transactionQueryOptions := TransactionQueryOptions{
				IncludeOnlyMostRecent: includeOnlyMostRecent,
			}
			// convert reportId to decimal
			hexStr := fmt.Sprintf("%.0f", reportId)
			reportIdDecimal, err := strconv.ParseInt(hexStr, 16, 64)
			if err != nil {
				panic(err)
			}
			log.Printf("🔎 Searching for onchain updates with Report ID : %s\n", toString(reportId))
			runFindWorkflowReportId(environmentStr, reportIdDecimal, transactionQueryOptions)
			return nil
		},
	}

	cmd.Flags().StringVarP(&environmentStr, "environment", "e", "staging", "Environment")
	cmd.Flags().Float64VarP(&reportId, "reportId", "r", 0, "Report ID to search")
	cmd.Flags().BoolVarP(&includeOnlyMostRecent, "includeOnlyMostRecent", "l", false, "Include only most recent transactions")

	cmd.MarkFlagRequired("reportId")
	cmd.MarkFlagRequired("environment")

	return &cmd
}

func runFindWorkflowReportId(env string, reportId int64, transactionQueryOptions TransactionQueryOptions) {
	accounts := GetAccountsByEnvironment(env)
	getReportProcessedEventsFromAccounts(reportId, accounts, env, transactionQueryOptions)

}

func getReportProcessedEventsFromAccounts(reportID int64, accounts []string, environment string, transactionQueryOptions TransactionQueryOptions) {
	log.Printf("fetching report processed events from environment %s\n", environment)

	var best *ReportProcessedEvent
	var bestTs int64
	for _, account := range accounts {
		transactions, _ := fetchTransactionsFromAccount(account, environment, transactionQueryOptions)
		for _, tx := range transactions {
			for _, event := range tx.Events {
				if !strings.HasSuffix(event.Type, "::forwarder::ReportProcessed") {
					continue
				}

				rid, ok := event.Data["report_id"]
				if !ok {
					continue
				}
				if int64(rid.(float64)) != reportID {
					continue
				}

				rec := ReportProcessedEvent{
					TransactionHash:     tx.Hash,
					BlockTimestamp:      tx.Timestamp,
					ReportId:            reportID,
					WorkflowExecutionId: toString(event.Data["workflow_execution_id"]),
				}

				blockTimestamp, err := strconv.ParseInt(tx.Timestamp, 10, 64)
				if err != nil {
					log.Println("Error parsing block_timestamp: %w", err)
					continue
				}

				if blockTimestamp > bestTs {
					tmp := rec
					best = &tmp
					bestTs = blockTimestamp
				}
			}
		}
	}

	if best != nil {
		network := GetAptosNetworkName(environment)
		t := time.UnixMicro(bestTs).UTC()
		date := t.Format("2006-01-02 15:04:05.000000")
		log.Printf("✅ Found matching reportID in transaction: 🔗 https://explorer.aptoslabs.com/txn/%s?network=%s. Date %s UTC", best.TransactionHash, network, date)
	} else {
		log.Printf("❌ No matching reportID found on chain")
	}

}
