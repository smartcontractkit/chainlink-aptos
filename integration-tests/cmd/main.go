package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap/zapcore"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/ccip"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-deployments-framework/engine/cld/legacy/cli"
)

func buildCmd(lggr logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "cmd",
	}

	// CCIP
	cmd.AddCommand(ccip.BuildCCIPCommand(lggr))

	return cmd
}

func main() {
	lggr, err := cli.NewCLILogger(zapcore.DebugLevel)
	if err != nil {
		fmt.Println("Failed to create logger:", err)
		os.Exit(1)
	}
	cmd := buildCmd(lggr)
	if err := cmd.Execute(); err != nil {
		lggr.Errorf("Failed to execute command: %v", err)
		os.Exit(1)
	}
}
