package monitor

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
)

// AptosAccBalanceMonitorOpts contains the options for creating a new Aptos account balance monitor.
type AptosAccBalanceMonitorOpts struct {
	ChainInfo ChainInfo

	Config    Config
	Logger    logger.Logger
	Keystore  core.Keystore
	NewClient func() (*aptos.NodeClient, error)
}

// NewAptosAccBalanceMonitor returns a balance monitoring services.Service which reports balance of all Keystore accounts.
func NewAptosAccBalanceMonitor(opts AptosAccBalanceMonitorOpts) (services.Service, error) {
	return NewBalanceMonitor(BalanceMonitorOpts{
		ChainInfo:           opts.ChainInfo,
		ChainNativeCurrency: "APT",

		Config:   opts.Config,
		Logger:   opts.Logger,
		Keystore: opts.Keystore,
		NewBalanceClient: func() (BalanceClient, error) {
			client, err := opts.NewClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get new client: %w", err)
			}
			return balanceClient{client}, nil
		},
	})
}

// Aptos balance reader client implementation
type balanceClient struct {
	client *aptos.NodeClient
}

// GetAccountBalance returns the account balance in APT.
func (c balanceClient) GetAccountBalance(addr string) (float64, error) {
	// Parse the address string
	accAddr := &aptos.AccountAddress{}
	err := accAddr.ParseStringRelaxed(addr)
	if err != nil {
		return -1, fmt.Errorf("failed to parse address [%s]: %w", addr, err)
	}

	// Get the account balance
	// Response is in octas or 1/10^8 APT.
	balance, err := c.client.AccountAPTBalance(*accAddr)
	return octaToAPT(balance), err
}

// Convert OCTA to APT as 1/10^8 APT
func octaToAPT(octa uint64) float64 {
	return float64(octa) / 100_000_000
}
