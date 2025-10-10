package ccip

import (
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/ccip/testhelpers"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func Test_CCIPDeployment(t *testing.T) {
	lggr := logger.Test(t)
	b, err := blockchain.NewBlockchainNetwork(&blockchain.Input{
		Type: blockchain.TypeAptos,
	})
	require.NoError(t, err)

	rpcUrl := b.Nodes[0].ExternalHTTPUrl + "/v1"

	lggr.Infof("Started Aptos Localnet at: %s", rpcUrl)

	client, err := aptos.NewNodeClient(rpcUrl, 0)
	require.NoError(t, err)

	pkBytes, err := crypto.ParsePrivateKey(blockchain.DefaultAptosPrivateKey, crypto.PrivateKeyVariantEd25519, false)
	require.NoError(t, err)
	privateKey := &crypto.Ed25519PrivateKey{}
	err = privateKey.FromBytes(pkBytes)
	require.NoError(t, err)
	account, err := aptos.NewAccountFromSigner(privateKey)
	require.NoError(t, err)

	bal, err := client.AccountAPTBalance(account.AccountAddress())
	require.NoError(t, err)
	lggr.Infof("Using account %v, balance %v APT", account.Address.StringLong(), bal/1e8)

	ccipDeployment, err := testhelpers.DeployCCIP(t.Context(), lggr, account, client)
	require.NoError(t, err)
	lggr.Infow("CCIP deployment successful.",
		"CCIP", ccipDeployment.CCIPAddress.StringLong(),
		"MCMS", ccipDeployment.MCMSAddress.StringLong(),
		"LINK", ccipDeployment.LINKAddress.StringLong(),
		"tokenPool", ccipDeployment.TokenPoolAddress.StringLong(),
	)

	tx, err := testhelpers.SendMessageFromAptos(t.Context(), lggr, account, client, ccipDeployment)
	require.NoError(t, err)
	lggr.Infof("Message sent successfully in tx: %v", tx)
}
