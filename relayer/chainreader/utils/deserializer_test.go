package utils

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCustomReportDeserializer(t *testing.T) {
	reportStr := "0xd91ad9c94fba41de8869e580deb6dbc08e84fb41431d41d04f8849ed00be4a070dca7c34e2f78ecdd91ad9c94fba41de15a9c133ee53500a0300000000000000000000000000000014e30b40bfb1baeed9e4c62f145be85eb3d19ae932184920616d206120746573742063636970206d6573736167654010af5717948371a0b649a59530f8e80e0e1247e015f05f1f3e09c715288dd040420f00000000000000000000000000000000000000000000000000000000000114bd10ffa3815c010d5cf7d38815a0eaabc959eb84a1b6cf2e878987deb2624f9a122297abf6332d45b48c4df6fc3ea705f810980fa08601002000000000000000000000000000000000000000000000000000000000000000120000c16ff2862300000000000000000000000000000000000000000000000000010000"
	data, err := hex.DecodeString(strings.TrimPrefix(reportStr, "0x"))
	require.NoError(t, err)

	report, err := DeserializeExecutionReport(data)
	require.NoError(t, err)

	t.Run("Verify integer values", func(t *testing.T) {
		require.Equal(t, uint64(16015286601757825753), report.SourceChainSelector)
		require.Equal(t, uint64(743186221051783445), report.Message.Header.DestChainSelector)
		require.Equal(t, uint64(3), report.Message.Header.SequenceNumber)
		require.Equal(t, uint64(0), report.Message.Header.Nonce)

		// Verify gas limit
		expectedGasLimit := big.NewInt(1000000)
		require.Equal(t, 0, expectedGasLimit.Cmp(report.Message.GasLimit))
	})

	t.Run("Verify token transfers", func(t *testing.T) {
		require.Len(t, report.Message.TokenAmounts, 1)
		tokenTransfer := report.Message.TokenAmounts[0]

		expectedAmount := big.NewInt(10000000000000000)
		require.Equal(t, 0, expectedAmount.Cmp(tokenTransfer.Amount))
		require.Equal(t, uint32(100000), tokenTransfer.DestGasAmount)
	})

	t.Run("Verify addresses", func(t *testing.T) {
		expectedReceiver := "0x4010af5717948371a0b649a59530f8e80e0e1247e015f05f1f3e09c715288dd0"
		require.Equal(t, expectedReceiver, report.Message.Receiver.String())

		expectedDestAddress := "0xa1b6cf2e878987deb2624f9a122297abf6332d45b48c4df6fc3ea705f810980f"
		require.Equal(t, expectedDestAddress, report.Message.TokenAmounts[0].DestTokenAddress.String())
	})

	t.Run("Verify message data", func(t *testing.T) {
		dataStr := string(report.Message.Data)
		require.Equal(t, "I am a test ccip message", dataStr)
	})
}
