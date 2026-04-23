package fakes

import (
	"context"
	"strings"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonCap "github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	aptosserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	mocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

const testAptosChainSelector uint64 = 4741433654826277352

func testKey(t *testing.T) *crypto.Ed25519PrivateKey {
	t.Helper()
	k, err := crypto.GenerateEd25519PrivateKey()
	require.NoError(t, err)
	return k
}

func testForwarder(t *testing.T) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed("0x1234"))
	return a
}

func newTestAptosChain(t *testing.T, client AptosClient, dryRun bool) *FakeAptosChain {
	t.Helper()
	fc, err := NewFakeAptosChain(logger.Test(t), client, testKey(t),
		testForwarder(t), testAptosChainSelector, dryRun)
	require.NoError(t, err)
	require.NotNil(t, fc)
	return fc
}

func TestFakeAptosChain_Construction(t *testing.T) {
	t.Parallel()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	assert.Equal(t, testAptosChainSelector, fc.ChainSelector())
	assert.Contains(t, strings.ToLower(fc.Name()), "aptos")
	assert.NotEmpty(t, fc.Description())
	info, err := fc.Info(t.Context())
	require.NoError(t, err)
	assert.Contains(t, info.ID, "4741433654826277352")
}

func TestFakeAptosChain_InterfaceAssertions(t *testing.T) {
	t.Parallel()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	var _ services.Service = fc
	var _ aptosserver.ClientCapability = fc
	var _ commonCap.ExecutableCapability = fc
}

func TestFakeAptosChain_Lifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	require.NoError(t, fc.Start(ctx))
	hr := fc.HealthReport()
	require.Len(t, hr, 1)
	assert.NoError(t, hr[fc.Name()])
	assert.NoError(t, fc.Close())
}

func TestFakeAptosChain_InitialiseStartsService(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)

	require.Error(t, fc.Ready(), "service should not be Ready before Initialise")

	require.NoError(t, fc.Initialise(ctx, core.StandardCapabilitiesDependencies{}))
	require.NoError(t, fc.Ready(), "Initialise must transition service to Started")
	assert.NoError(t, fc.HealthReport()[fc.Name()])

	require.NoError(t, fc.Close())
}

func TestFakeAptosChain_InterfaceShims(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	fc := newTestAptosChain(t, mocks.NewAptosRpcClient(t), false)
	require.NoError(t, fc.Initialise(ctx, core.StandardCapabilitiesDependencies{}))
	require.NoError(t, fc.RegisterToWorkflow(ctx, commonCap.RegisterToWorkflowRequest{Metadata: commonCap.RegistrationMetadata{WorkflowID: "w1"}}))
	require.NoError(t, fc.UnregisterFromWorkflow(ctx, commonCap.UnregisterFromWorkflowRequest{Metadata: commonCap.RegistrationMetadata{WorkflowID: "w1"}}))
	resp, err := fc.Execute(ctx, commonCap.CapabilityRequest{})
	require.NoError(t, err)
	assert.Equal(t, commonCap.CapabilityResponse{}, resp)
}

func TestFakeAptosChain_NilClient(t *testing.T) {
	t.Parallel()
	_, err := NewFakeAptosChain(logger.Test(t), nil, testKey(t), testForwarder(t), testAptosChainSelector, false)
	require.Error(t, err)
}

func TestFakeAptosChain_NilKey(t *testing.T) {
	t.Parallel()
	_, err := NewFakeAptosChain(logger.Test(t), mocks.NewAptosRpcClient(t), nil, testForwarder(t), testAptosChainSelector, false)
	require.Error(t, err)
}
