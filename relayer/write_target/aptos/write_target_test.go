package write_target_test

import (
	"testing"

	chainmocks "github.com/smartcontractkit/chainlink-aptos/relayer/chain/mock"
	write_target "github.com/smartcontractkit/chainlink-aptos/relayer/write_target/aptos"
	"github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/tests"
	"github.com/stretchr/testify/require"
)

func TestWriteTarget(t *testing.T) {
	ctx := tests.Context(t)
	lggr := logger.Test(t)
	mockChain := chainmocks.NewChain(t)

	wt, err := write_target.NewAptosWriteTarget(ctx, mockChain, lggr)
	require.NoError(t, err)

	res, err := wt.Execute(ctx, capabilities.CapabilityRequest{})
	require.NoError(t, err)
	_ = res
}
