package forwarder_mcms_adapter

import (
	"bytes"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

// reference BCS-encodes args with the generic, type-string driven encoder and concatenates them,
// which is exactly the data layout mcms_entrypoint decodes.
func reference(t *testing.T, types []string, values []any) []byte {
	t.Helper()
	c := bind.NewBoundContract(aptos.AccountAddress{}, "", "", nil)
	_, _, _, args, err := c.Encode("", nil, types, values)
	require.NoError(t, err)
	return bytes.Join(args, nil)
}

func TestEncoder(t *testing.T) {
	var adapter, fwd, to aptos.AccountAddress
	require.NoError(t, adapter.ParseStringRelaxed("0xada"))
	require.NoError(t, fwd.ParseStringRelaxed("0x100"))
	require.NoError(t, to.ParseStringRelaxed("0xb0b"))
	oracles := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)}

	e := NewEncoder(adapter)

	module, fn, data, err := e.SetConfig(fwd, 7, 3, 1, oracles)
	require.NoError(t, err)
	require.Equal(t, FunctionSetConfig, fn)
	require.Equal(t, bind.ModuleInformation{PackageName: string(contracts.ForwarderMcmsAdapter), ModuleName: "adapter", Address: adapter}, module)
	require.Equal(t, reference(t,
		[]string{"address", "u32", "u32", "u8", "vector<vector<u8>>"},
		[]any{fwd, uint32(7), uint32(3), uint8(1), oracles}), data)

	_, fn, data, err = e.ClearConfig(fwd, 7, 3)
	require.NoError(t, err)
	require.Equal(t, FunctionClearConfig, fn)
	require.Equal(t, reference(t, []string{"address", "u32", "u32"}, []any{fwd, uint32(7), uint32(3)}), data)

	_, fn, data, err = e.TransferOwnership(fwd, to)
	require.NoError(t, err)
	require.Equal(t, FunctionTransferOwnership, fn)
	require.Equal(t, reference(t, []string{"address", "address"}, []any{fwd, to}), data)

	_, fn, data, err = e.AcceptOwnership(fwd)
	require.NoError(t, err)
	require.Equal(t, FunctionAcceptOwnership, fn)
	require.Equal(t, reference(t, []string{"address"}, []any{fwd}), data)
}
