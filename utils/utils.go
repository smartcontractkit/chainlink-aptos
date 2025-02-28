package utils

import (
	"fmt"

	"github.com/smartcontractkit/chainlink/deployment"
)

// TODO: This function will be used directly, but it need to be a parameter of AptosChain
// to be consistent to Evm/Solana pattern
func ConfirmTx(chain deployment.AptosChain, txHash string) error {
	userTx, err := chain.Client.WaitForTransaction(txHash)
	if err != nil {
		return err
	}
	if !userTx.Success {
		return fmt.Errorf("transaction failed: %s", userTx.VmStatus)
	}
	return nil
}
