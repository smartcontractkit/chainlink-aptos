package chainreader

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	aptos0 "github.com/smartcontractkit/chainlink-common/pkg/types/aptos"
	ccipconsts "github.com/smartcontractkit/chainlink-common/pkg/types/ccip/consts"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"

	aptosloop "github.com/smartcontractkit/chainlink-aptos/codec/loop"
)

var routerBinding = types.BoundContract{
	Address: "0x0000000000000000000000000000000000000000000000000000000000000123",
	Name:    ccipconsts.ContractNameRouter,
}

// APT primary fungible asset address, asserted independently of aptNativeTokenAddress.
const wantAPTAddress = "0x000000000000000000000000000000000000000000000000000000000000000a"

func TestRouterGetWrappedNative(t *testing.T) {
	t.Parallel()

	t.Run("loop mode returns the JSON-encoded address", func(t *testing.T) {
		t.Parallel()

		reader := NewChainReader(logger.Test(t), nil, aptos0.ContractReaderConfig{IsLoopPlugin: true}, nil, nil)
		require.NoError(t, reader.Bind(t.Context(), []types.BoundContract{routerBinding}))

		var out []byte
		err := reader.GetLatestValue(t.Context(), routerBinding.ReadIdentifier(ccipconsts.MethodNameRouterGetWrappedNative), primitives.Finalized, nil, &out)
		require.NoError(t, err)

		var got string
		require.NoError(t, json.Unmarshal(out, &got))
		require.Equal(t, wantAPTAddress, got)
	})

	t.Run("non-loop mode returns the 32-byte address", func(t *testing.T) {
		t.Parallel()

		reader := NewChainReader(logger.Test(t), nil, aptos0.ContractReaderConfig{}, nil, nil)
		require.NoError(t, reader.Bind(t.Context(), []types.BoundContract{routerBinding}))

		out := []byte{}
		err := reader.GetLatestValue(t.Context(), routerBinding.ReadIdentifier(ccipconsts.MethodNameRouterGetWrappedNative), primitives.Finalized, nil, &out)
		require.NoError(t, err)

		require.Len(t, out, 32)
		require.Equal(t, wantAPTAddress, "0x"+hex.EncodeToString(out))
	})

	t.Run("other Router reads still fail on the missing module", func(t *testing.T) {
		t.Parallel()

		reader := NewChainReader(logger.Test(t), nil, aptos0.ContractReaderConfig{}, nil, nil)
		require.NoError(t, reader.Bind(t.Context(), []types.BoundContract{routerBinding}))

		out := []byte{}
		err := reader.GetLatestValue(t.Context(), routerBinding.ReadIdentifier("GetOwner"), primitives.Finalized, nil, &out)
		require.ErrorContains(t, err, "no such contract: Router")
	})

	t.Run("unbound Router still fails on the missing binding", func(t *testing.T) {
		t.Parallel()

		reader := NewChainReader(logger.Test(t), nil, aptos0.ContractReaderConfig{}, nil, nil)

		out := []byte{}
		err := reader.GetLatestValue(t.Context(), routerBinding.ReadIdentifier(ccipconsts.MethodNameRouterGetWrappedNative), primitives.Finalized, nil, &out)
		require.ErrorContains(t, err, "no bound address for module Router")
	})

	t.Run("through the loop reader the address decodes to 32 bytes", func(t *testing.T) {
		t.Parallel()

		inner := NewChainReader(logger.Test(t), nil, aptos0.ContractReaderConfig{IsLoopPlugin: true}, nil, nil)
		loopReader := aptosloop.NewLoopChainReader(logger.Test(t), inner)
		require.NoError(t, loopReader.Bind(t.Context(), []types.BoundContract{routerBinding}))

		var out []byte
		err := loopReader.GetLatestValue(t.Context(), routerBinding.ReadIdentifier(ccipconsts.MethodNameRouterGetWrappedNative), primitives.Finalized, nil, &out)
		require.NoError(t, err)

		require.Len(t, out, 32)
		require.Equal(t, wantAPTAddress, "0x"+hex.EncodeToString(out))
	})
}
