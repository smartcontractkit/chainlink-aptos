package ccip

import (
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/ccip/testhelpers"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-testing-framework/framework/components/blockchain"
)

func Test_CCIPDeployment(t *testing.T) {
	b, err := blockchain.NewBlockchainNetwork(&blockchain.Input{
		Type: blockchain.TypeAptos,
	})
	require.NoError(t, err)

	rpcUrl := b.Nodes[0].ExternalHTTPUrl + "/v1"

	t.Logf("Started Aptos Localnet at: %v", rpcUrl)

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
	t.Logf("Using account %v, balance: %v APT", account.Address.String(), bal/1e8)

	ccipDeployment, err := testhelpers.DeployCCIP(t.Context(), account, client)
	require.NoError(t, err)
	t.Logf("CCIP deployment successful:")
	t.Logf("\t CCIP: %v", ccipDeployment.CCIPAddress.StringLong())
	t.Logf("\t MCMS: %v", ccipDeployment.MCMSAddress.StringLong())
	t.Logf("\t LINK: %v", ccipDeployment.LINKAddress.StringLong())
	t.Logf("\t Token Pool: %v", ccipDeployment.TokenPoolAddress.StringLong())

	tx, err := testhelpers.SendMessageFromAptos(t.Context(), account, client, ccipDeployment)
	require.NoError(t, err)
	t.Logf("Message sent successfully in tx: %v", tx)
}
