package testutils

import (
	"strconv"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
)

func CompileTestModule(t *testing.T, moduleAddress aptos.AccountAddress) CompilationResult {
	return CompileMovePackage(t, "test", map[string]aptos.AccountAddress{
		"test": moduleAddress,
	})
}

func HasCounterResource(client *aptos.NodeClient, counterAddress aptos.AccountAddress) bool {
	_, err := client.AccountResource(counterAddress, counterAddress.String()+"::counter::Counter")
	return err == nil
}

func ReadCounterValue(t *testing.T, client *aptos.NodeClient, counterAddress aptos.AccountAddress) uint64 {
	resource, err := client.AccountResource(counterAddress, counterAddress.String()+"::counter::Counter")
	require.NoError(t, err)

	data, ok := resource["data"]
	require.True(t, ok)

	dataMap, ok := data.(map[string]any)
	require.True(t, ok)

	value, ok := dataMap["value"]
	require.True(t, ok)

	valueStr, ok := value.(string)
	require.True(t, ok)

	valueInt, err := strconv.ParseUint(valueStr, 10, 64)
	require.NoError(t, err)

	return valueInt
}
