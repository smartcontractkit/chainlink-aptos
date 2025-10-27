package monitor

import (
	"context"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

// BalanceMonitorOpts contains the options for creating a new Aptos account balance monitor.
type BalanceMonitorOpts struct {
	ChainInfo types.ChainInfo

	Config    GenericBalanceConfig
	Logger    logger.Logger
	Keystore  core.Keystore
	NewClient func() (aptos.AptosRpcClient, error)
}

// NewBalanceMonitor returns a balance monitoring services.Service which reports balance of all Keystore accounts.
func NewBalanceMonitor(opts BalanceMonitorOpts) (services.Service, error) {
	return NewGenericBalanceMonitor(GenericBalanceMonitorOpts{
		ChainInfo:           opts.ChainInfo,
		ChainNativeCurrency: "APT",

		Config:   opts.Config,
		Logger:   opts.Logger,
		Keystore: opts.Keystore,
		NewGenericBalanceClient: func() (GenericBalanceClient, error) {
			client, err := opts.NewClient()
			if err != nil {
				return nil, fmt.Errorf("failed to get new client: %w", err)
			}
			return balanceClient{client}, nil
		},
		KeyToAccountMapper: func(ctx context.Context, pk string) (string, error) {
			// We need to convert the Aptos public key to an account address
			return utils.HexPublicKeyToAddressString(pk)
		},
	})
}

// Aptos balance reader client implementation
type balanceClient struct {
	client aptos.AptosRpcClient
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
