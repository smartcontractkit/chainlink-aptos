package relayer

import (
	"context"
	"testing"

	aptos_sdk "github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/chains/aptos"

	chainconfig "github.com/smartcontractkit/chainlink-aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	clientmocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
	"github.com/smartcontractkit/chainlink-aptos/relayer/transmitter"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	aptosutils "github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

func TestAptosServiceLedgerVersion(t *testing.T) {
	t.Parallel()

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().Info().Return(aptos_sdk.NodeInfo{LedgerVersionStr: "12345"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	got, err := svc.LedgerVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, uint64(12345), got)
}

func TestAptosServiceViewUsesLatestWhenLedgerVersionIsNil(t *testing.T) {
	t.Parallel()

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().View(mock.Anything).Run(func(payload *aptos_sdk.ViewPayload, ledgerVersion ...uint64) {
		require.Equal(t, "balance", payload.Function)
		require.Empty(t, ledgerVersion)
	}).Return([]any{"ok"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.View(context.Background(), aptos.ViewRequest{
		Payload: &aptos.ViewPayload{
			Module: aptos.ModuleID{
				Address: aptos.AccountAddress{1},
				Name:    "coin",
			},
			Function: "balance",
		},
	})
	require.NoError(t, err)
	require.JSONEq(t, `["ok"]`, string(reply.Data))
}

func TestAptosServiceViewUsesRequestedLedgerVersion(t *testing.T) {
	t.Parallel()

	const ledgerVersion = uint64(77)
	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().View(mock.Anything, ledgerVersion).Run(func(payload *aptos_sdk.ViewPayload, versions ...uint64) {
		require.Equal(t, "balance", payload.Function)
		require.Len(t, versions, 1)
		require.Equal(t, ledgerVersion, versions[0])
	}).Return([]any{"ok"}, nil).Once()

	svc := aptosService{
		chain:  &testChain{client: client},
		logger: logger.Test(t),
	}

	reply, err := svc.View(context.Background(), aptos.ViewRequest{
		Payload: &aptos.ViewPayload{
			Module: aptos.ModuleID{
				Address: aptos.AccountAddress{1},
				Name:    "coin",
			},
			Function: "balance",
		},
		LedgerVersion: ptrUint64(ledgerVersion),
	})
	require.NoError(t, err)
	require.JSONEq(t, `["ok"]`, string(reply.Data))
}

func ptrUint64(v uint64) *uint64 {
	return &v
}

// getAccountWithHighestBalance must query each keystore public key at its
// configured transmitter address. Strict mock expectations encode the
// contract: derivedA for pubKeyA, overrideB for pubKeyB. If the resolver
// returned pubKeyB's derived address, the mock would fail on the unexpected
// call.
func TestAptosService_GetAccountWithHighestBalance_HonorsTransmitterOverride(t *testing.T) {
	t.Parallel()

	const (
		pubKeyA      = "abababababababababababababababababababababababababababababababab"
		pubKeyB      = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
		overrideAddr = "0x2222222222222222222222222222222222222222222222222222222222222222"
	)

	var overrideB aptos_sdk.AccountAddress
	require.NoError(t, overrideB.ParseStringRelaxed(overrideAddr))
	derivedA, err := aptosutils.HexPublicKeyToAddress(pubKeyA)
	require.NoError(t, err)

	client := clientmocks.NewAptosRpcClient(t)
	client.EXPECT().AccountAPTBalance(derivedA).Return(uint64(10), nil).Once()
	client.EXPECT().AccountAPTBalance(overrideB).Return(uint64(100), nil).Once()

	cfg := &chainconfig.TOMLConfig{
		Chain: chainconfig.Chain{
			Transmitter: &transmitter.Config{Overrides: map[string]string{pubKeyB: overrideAddr}},
		},
	}
	svc := aptosService{
		chain:  &testChain{client: client, config: cfg},
		logger: logger.Test(t),
	}

	selected, _ := svc.getAccountWithHighestBalance(context.Background(), []string{pubKeyA, pubKeyB})
	require.Equal(t, pubKeyB, selected, "picker must select the key whose resolved address holds the higher balance")
}

type testChain struct {
	commontypes.UnimplementedChainService
	client aptos_sdk.AptosRpcClient
	config *chainconfig.TOMLConfig
}

func (t testChain) Start(context.Context) error {
	return nil
}

func (t testChain) Close() error {
	return nil
}

func (t testChain) Ready() error {
	return nil
}

func (t testChain) Name() string {
	return "test-chain"
}

func (t testChain) HealthReport() map[string]error {
	return map[string]error{}
}

func (t testChain) ID() string {
	return "1"
}

func (t testChain) Config() *chainconfig.TOMLConfig {
	if t.config != nil {
		return t.config
	}
	return &chainconfig.TOMLConfig{}
}

func (t testChain) DataSource() sqlutil.DataSource {
	return nil
}

func (t testChain) TxManager() *txm.AptosTxm {
	return nil
}

func (t testChain) LogPoller() *logpoller.AptosLogPoller {
	return nil
}

func (t testChain) GetClient() (aptos_sdk.AptosRpcClient, error) {
	return t.client, nil
}

func (t testChain) KeyStore() loop.Keystore {
	return nil
}
