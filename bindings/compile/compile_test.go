//go:build aptoscli

package compile

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

func TestCompileMCMS(t *testing.T) {
	output, err := CompilePackage(contracts.MCMS, map[string]aptos.AccountAddress{
		"mcms":       aptos.AccountThree,
		"mcms_owner": aptos.AccountFour,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}

func TestCompileLargePackages(t *testing.T) {
	output, err := CompilePackage(contracts.LargePackages, map[string]aptos.AccountAddress{
		"large_packages": aptos.AccountThree,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}

func TestCompileCCIP(t *testing.T) {
	output, err := CompilePackage(contracts.CCIP, map[string]aptos.AccountAddress{
		"ccip":                      aptos.AccountThree,
		"mcms":                      aptos.AccountFour,
		"mcms_register_entrypoints": aptos.AccountZero,
	})
	require.NoError(t, err)

	require.NotNil(t, output.Metadata)
	require.NotZero(t, output.Bytecode)
}
