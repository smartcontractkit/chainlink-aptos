package aptos

import (
	"context"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	rlclient "github.com/smartcontractkit/chainlink-aptos/relayer/client"
	"github.com/smartcontractkit/chainlink-framework/capabilities/writetarget/beholder/monitor"
)

// BalanceMonitorOpts contains the options for creating a new Aptos account balance monitor.
type BalanceMonitorOpts struct {
	ChainInfo monitor.ChainInfo

	Config    monitor.Config
	Logger    logger.Logger
	Keystore  core.Keystore
	NewClient func() (rlclient.RateLimitedClient, error)
}

// NewBalanceMonitor returns a balance monitoring services.Service which reports balance of all Keystore accounts.
func NewBalanceMonitor(opts BalanceMonitorOpts) (services.Service, error) {
	return monitor.NewBalanceMonitor(monitor.BalanceMonitorOpts{
		ChainInfo:           opts.ChainInfo,
		ChainNativeCurrency: "APT",

		Config:   opts.Config,
		Logger:   opts.Logger,
		Keystore: opts.Keystore,
		NewBalanceClient: func() (monitor.BalanceClient, error) {
			client, err := opts.NewClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get new client: %w", err)
			}
			return balanceClient{client}, nil
		},
		KeyToAccountMapper: func(ctx context.Context, pk string) (string, error) {
			// We need to convert the Aptos public key to an account address
			return HexPublicKeyToAccountAddrString(pk)
		},
	})
}

// Aptos balance reader client implementation
type balanceClient struct {
	client rlclient.RateLimitedClient
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
