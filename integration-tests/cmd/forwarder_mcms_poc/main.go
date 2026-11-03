// Command forwarder_mcms_poc proves that MCMS can control a forwarder that has no MCMS integration,
// by routing calls through an adapter package:
//
//	mcms (dispatch hook) -> forwarder_mcms_adapter::adapter::mcms_entrypoint (static call) -> dummy_forwarder::forwarder
//
// Run the steps in order (or `all`). Deployed addresses are persisted to --state-file so each step
// can be re-run on its own.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var flags envFlags

	cmd := &cobra.Command{
		Use:          "forwarder_mcms_poc",
		Short:        "PoC: MCMS -> adapter -> forwarder on Aptos",
		SilenceUsage: true,
	}
	cmd.PersistentFlags().StringVar(&flags.rpcURL, "rpc-url", envOr("APTOS_RPC_URL", "https://api.testnet.aptoslabs.com/v1"), "Aptos node REST URL")
	cmd.PersistentFlags().StringVar(&flags.deployerKey, "deployer-key", os.Getenv("DEPLOYER_KEY"), "ed25519 private key of the deployer (hex, optionally ed25519-priv- prefixed). Env: DEPLOYER_KEY")
	cmd.PersistentFlags().StringVar(&flags.mcmsSignerKey, "mcms-signer-key", os.Getenv("MCMS_SIGNER_KEY"), "secp256k1 private key (hex) of the single MCMS signer. Generated and saved to the state file if unset. Env: MCMS_SIGNER_KEY")
	cmd.PersistentFlags().StringVar(&flags.stateFile, "state-file", "poc-state.json", "file to persist deployed addresses")
	cmd.PersistentFlags().Uint64Var(&flags.deployMaxGas, "deploy-max-gas", 2_000_000, "max gas for package deployments (the account must hold max_gas * gas_price)")

	run := func(fn func(*env, []string) error) func(*cobra.Command, []string) error {
		return func(c *cobra.Command, args []string) error {
			e, err := newEnv(c.Context(), flags)
			if err != nil {
				return err
			}
			return fn(e, args)
		}
	}

	cmd.AddCommand(
		&cobra.Command{
			Use:   "deploy-forwarder",
			Short: "Deploy dummy_forwarder to a new code object, owned by the deployer",
			RunE:  run(func(e *env, _ []string) error { return e.deployForwarder() }),
		},
		&cobra.Command{
			Use:   "set-value N",
			Short: "Call forwarder::set_value directly with the deployer key",
			Args:  cobra.ExactArgs(1),
			RunE: run(func(e *env, args []string) error {
				n, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return err
				}
				return e.setValueDirect(n)
			}),
		},
		&cobra.Command{
			Use:   "status",
			Short: "Print forwarder value / owner and MCMS-related addresses",
			RunE:  run(func(e *env, _ []string) error { return e.printStatus() }),
		},
		&cobra.Command{
			Use:   "deploy-mcms",
			Short: "Deploy MCMS and configure the bypasser role as 1-of-1 with the MCMS signer key",
			RunE:  run(func(e *env, _ []string) error { return e.deployMCMS() }),
		},
		&cobra.Command{
			Use:   "deploy-adapter",
			Short: "Deploy forwarder_mcms_adapter (depends on MCMS + dummy_forwarder); registers its MCMS entrypoint",
			RunE:  run(func(e *env, _ []string) error { return e.deployAdapter() }),
		},
		&cobra.Command{
			Use:   "transfer-to-mcms",
			Short: "Deployer proposes the adapter's MCMS owner as forwarder owner; MCMS accepts through the adapter",
			RunE:  run(func(e *env, _ []string) error { return e.transferToMCMS() }),
		},
		&cobra.Command{
			Use:   "mcms-set-value N",
			Short: "Set the forwarder value via an MCMS proposal through the adapter",
			Args:  cobra.ExactArgs(1),
			RunE: run(func(e *env, args []string) error {
				n, err := strconv.ParseUint(args[0], 10, 64)
				if err != nil {
					return err
				}
				return e.mcmsSetValue(n)
			}),
		},
		&cobra.Command{
			Use:   "mcms-transfer-back",
			Short: "MCMS proposes the deployer as forwarder owner (via adapter); deployer accepts",
			RunE:  run(func(e *env, _ []string) error { return e.transferBack() }),
		},
		&cobra.Command{
			Use:   "all",
			Short: "Run every step in order",
			RunE: run(func(e *env, _ []string) error {
				steps := []func() error{
					e.deployForwarder,
					func() error { return e.setValueDirect(7) },
					e.deployMCMS,
					e.deployAdapter,
					e.transferToMCMS,
					func() error { return e.mcmsSetValue(42) },
					e.printStatus,
				}
				for _, step := range steps {
					if err := step(); err != nil {
						return err
					}
				}
				return nil
			}),
		},
	)
	return cmd
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
