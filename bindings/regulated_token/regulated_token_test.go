package regulated_token

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

func TestCompile(t *testing.T) {
	t.Parallel()
	output, err := Compile(aptos.AccountOne, aptos.AccountTwo)
	require.NoError(t, err)
	require.NotZero(t, output.Metadata, "Compilation resulted in no metadata")
	require.NotZero(t, output.Bytecode, "Compilation resulted in no bytecode")
}

func TestCompileMCMSRegistrar(t *testing.T) {
	t.Parallel()
	output, err := CompileMCMSRegistrar(aptos.AccountOne, aptos.AccountTwo, aptos.AccountTwo, false)
	require.NoError(t, err)
	require.NotZero(t, output.Metadata, "Compilation resulted in no metadata")
	require.NotZero(t, output.Bytecode, "Compilation resulted in no bytecode")
}
