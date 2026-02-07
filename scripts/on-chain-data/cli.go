package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := buildCmd()
	if err := cmd.Execute(); err != nil {
		log.Fatal("failed to execute command: %w", err)
		os.Exit(1)
	}
}

func buildCmd() *cobra.Command {
	pCmd := &cobra.Command{Use: "Aptos On Chain Data", Short: "Aptos On Chain Data"}

	pCmd.AddCommand(BuildMGetFeedUpdatedEvents())
	pCmd.AddCommand(BuildComputeDataFeedUpdatedEventsMetrics())
	pCmd.AddCommand(BuildMGetAccountBalances())
	pCmd.AddCommand(BuildFindFeedUpdateWorkflowReportId())

	return pCmd
}
