package ccip

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/spf13/cobra"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/ccip/testhelpers"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

const (
	privateKeyFlag = "privateKey"
	rpcUrlFlag     = "rpcUrl"
	faucetUrlFlag  = "faucetUrl"
	fundAmountFlag = "fundAmount"
)

func buildCCIPDeployCmd(lggr logger.Logger) *cobra.Command {
	var (
		aptosPrivateKey string
		aptosRpcUrl     string
		faucetUrl       string
		fundAmount      uint64
	)

	cmd := &cobra.Command{
		Use: "deploy",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := aptos.NewNodeClient(aptosRpcUrl, 0)
			if err != nil {
				return err
			}

			var account *aptos.Account
			if aptosPrivateKey != "" {
				pkBytes, err := crypto.ParsePrivateKey(aptosPrivateKey, crypto.PrivateKeyVariantEd25519, false)
				if err != nil {
					return err
				}
				privateKey := &crypto.Ed25519PrivateKey{}
				err = privateKey.FromBytes(pkBytes)
				if err != nil {
					return err
				}
				account, err = aptos.NewAccountFromSigner(privateKey)
				if err != nil {
					return err
				}
				lggr.Debugf("Using account %v", account.Address.StringLong())
			} else {
				account, err = aptos.NewEd25519Account()
				if err != nil {
					return fmt.Errorf("failed to generate new random account: %w", err)
				}
				pk, err := account.PrivateKeyString()
				if err != nil {
					return err
				}
				lggr.Debugf("Using random account %v (private key: %v)", account.Address.String(), pk)
				if fundAmount == 0 {
					fundAmount = 100
					lggr.Debugf("Using a random account but no funding amount was specified. Funding with 100 APT instead")
				}
			}

			if fundAmount > 0 {
				faucetClient, err := aptos.NewFaucetClient(client, faucetUrl)
				if err != nil {
					return fmt.Errorf("failed to create faucet client: %w", err)
				}
				err = faucetClient.Fund(account.AccountAddress(), fundAmount*1e8)
				if err != nil {
					return fmt.Errorf("failed to fund %v with %v APT: %w", account.Address.StringLong(), fundAmount, err)
				}
				lggr.Debugf("Successfully funded %v with %v APT", account.Address.StringLong(), fundAmount)
			}

			bal, err := client.AccountAPTBalance(account.AccountAddress())
			if err != nil {
				return err
			}
			lggr.Debugf("Using account %v, balance: %v APT", account.Address.StringLong(), bal/1e8)

			ccipDeployment, err := testhelpers.DeployCCIP(cmd.Context(), lggr, account, client)
			if err != nil {
				return fmt.Errorf("failed to deploy CCIP: %w", err)
			}

			lggr.Info("CCIP deployment successful:")
			lggr.Infof("CCIP: %v", ccipDeployment.CCIPAddress.StringLong())
			lggr.Infof("MCMS: %v", ccipDeployment.MCMSAddress.StringLong())
			lggr.Infof("LINK: %v", ccipDeployment.LINKAddress.StringLong())
			lggr.Infof("Token Pool: %v", ccipDeployment.TokenPoolAddress.StringLong())

			return nil
		},
	}

	cmd.PersistentFlags().StringVarP(&aptosPrivateKey, privateKeyFlag, "k", "", "The Aptos private key to use for the deployment. If not specified, a random key will be generated and funded with 100 APT using the faucet")
	cmd.PersistentFlags().StringVarP(&aptosRpcUrl, rpcUrlFlag, "r", "http://localhost:8080/v1", "The Aptos RPC URL to use")
	cmd.PersistentFlags().StringVar(&faucetUrl, faucetUrlFlag, "http://localhost:8081/", "The Faucet URL to use")
	cmd.PersistentFlags().Uint64Var(&fundAmount, fundAmountFlag, 0, "The amount of APT to fund the account with. If specified, will use the provided faucet to fund the deployer account")

	return cmd
}

func BuildCCIPCommand(lggr logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "ccip",
	}

	cmd.AddCommand(buildCCIPDeployCmd(lggr))

	return cmd
}
