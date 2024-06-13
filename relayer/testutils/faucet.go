package testutils

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func FundWithFaucet(logger logger.Logger, client *aptos.NodeClient, address aptos.AccountAddress, faucetUrl string) error {
	faucetClient, err := aptos.NewFaucetClient(client, faucetUrl)
	if err != nil {
		return fmt.Errorf("failed to create faucet client: %+w", err)
	}

	if err := faucetClient.Fund(address, 100*100000000); err != nil {
		return fmt.Errorf("failed to fund with faucet: %+w", err)
	}

	logger.Debugw("Funded using faucet", "address", address.String())
	return nil
}
