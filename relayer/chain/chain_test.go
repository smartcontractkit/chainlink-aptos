package chain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/config"
)

func newTestTOMLConfig(t *testing.T) *config.TOMLConfig {
	t.Helper()
	cfg, err := config.NewDecodedTOMLConfig(`
ChainID = "2"

[[Nodes]]
Name = "primary"
URL = "http://localhost:8080"

[[Nodes]]
Name = "secondary"
URL = "http://localhost:8081"
`)
	require.NoError(t, err)
	return cfg
}

func TestNewMultiNode(t *testing.T) {
	t.Parallel()

	cfg := newTestTOMLConfig(t)
	mn, err := newMultiNode(cfg, logger.Test(t))
	require.NoError(t, err)
	require.NotNil(t, mn)

	// An unstarted pool has no live node, so selection fails fast rather than returning a
	// usable client. This is the path that surfaces multinode.ErrNodeError through GetMultiNodeClient.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = mn.SelectRPC(ctx)
	require.Error(t, err)
}
