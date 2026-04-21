package fakes

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	mocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

// Compile-time assertions: real SDK client and mockery mock both satisfy AptosClient.
var (
	_ AptosClient = (*aptos.Client)(nil)
	_ AptosClient = (*mocks.AptosRpcClient)(nil)
)

func TestNewAptosClient_BuildsForValidURL(t *testing.T) {
	c, err := NewAptosClient("https://fullnode.devnet.aptoslabs.com/v1")
	require.NoError(t, err)
	require.NotNil(t, c)
}
