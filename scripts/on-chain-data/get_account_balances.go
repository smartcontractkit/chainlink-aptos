package main

import (
	"log"

	"github.com/spf13/cobra"
)

func BuildMGetAccountBalances() *cobra.Command {
	var (
		environment string
	)

	cmd := cobra.Command{
		Use:   "get-account-balances",
		Short: "Get account balances",
		RunE: func(cmd *cobra.Command, args []string) error {
			runGetAccountBalances(environment)
			return nil
		},
	}

	cmd.Flags().StringVarP(&environment, "environment", "e", "staging", "Environment")
	cmd.MarkFlagRequired("environment")

	return &cmd
}

func runGetAccountBalances(env string) {
	log.Printf("getting account balances for environemnt %s", env)
	accounts := GetAccountsByEnvironment(env)

	for _, account := range accounts {
		balance, _ := GetAccountBalanceByEnvironment(account, env)
		log.Printf("account %s has balance: %d", account, balance)
	}
}
