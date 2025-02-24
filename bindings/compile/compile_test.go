//go:build aptoscli

package compile

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

func TestCompileMCMS(t *testing.T) {
	output, err := CompilePackage("mcms", map[string]aptos.AccountAddress{
		"mcms":       aptos.AccountThree,
		"mcms_owner": aptos.AccountFour,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}

func TestCompileLargePackages(t *testing.T) {
	output, err := CompilePackage("large_packages", map[string]aptos.AccountAddress{
		"large_packages": aptos.AccountThree,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}

func TestCompileCCIP(t *testing.T) {
	output, err := CompilePackage("ccip", map[string]aptos.AccountAddress{
		"ccip": aptos.AccountThree,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}
