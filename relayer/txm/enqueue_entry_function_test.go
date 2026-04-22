package txm

import (
	"strings"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

// 32-byte ed25519 public key hex (all 0xab).
const testPubKeyHex = "abababababababababababababababababababababababababababababababab"

func newTestTxm(t *testing.T) *AptosTxm {
	t.Helper()
	cfg := DefaultConfigSet
	cfg.Resolve()
	return &AptosTxm{
		baseLogger:    logger.Test(t),
		config:        cfg,
		transactions:  make(map[string]*AptosTx),
		broadcastChan: make(chan string, 1),
	}
}

func mustAddress(t *testing.T, hex string) aptos.AccountAddress {
	t.Helper()
	var a aptos.AccountAddress
	require.NoError(t, a.ParseStringRelaxed(hex))
	return a
}

func sampleEntryFunction(t *testing.T) *aptos.EntryFunction {
	t.Helper()
	return &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: mustAddress(t, "0x1"),
			Name:    "counter",
		},
		Function: "increment",
		ArgTypes: []aptos.TypeTag{},
		Args:     [][]byte{},
	}
}

// EnqueueWithEntryFunction must honor a non-zero fromAddress override, even when
// that address does not match the one the public key would derive to.
func TestEnqueueWithEntryFunction_OverrideFromAddress(t *testing.T) {
	txm := newTestTxm(t)

	override := mustAddress(t, "0x1111111111111111111111111111111111111111111111111111111111111111")
	derived, err := utils.HexPublicKeyToAddress(testPubKeyHex)
	require.NoError(t, err)
	require.NotEqual(t, derived.String(), override.String(), "test fixture must use an override different from the derived address")

	id, err := txm.EnqueueWithEntryFunction("tx-override", &commontypes.TxMeta{}, testPubKeyHex, override, sampleEntryFunction(t), false)
	require.NoError(t, err)

	tx, ok := txm.transactions[id]
	require.True(t, ok, "tx should be stored")
	assert.Equal(t, strings.ToLower(override.String()), strings.ToLower(tx.FromAddress.String()), "FromAddress must equal the override, not the derived address")
	assert.NotEqual(t, derived.String(), tx.FromAddress.String())
}

// EnqueueWithEntryFunction with zero fromAddress falls back to deriving from the
// public key (preserves original behavior for non-rotated accounts).
func TestEnqueueWithEntryFunction_ZeroFromAddressDerives(t *testing.T) {
	txm := newTestTxm(t)

	derived, err := utils.HexPublicKeyToAddress(testPubKeyHex)
	require.NoError(t, err)

	id, err := txm.EnqueueWithEntryFunction("tx-derive", &commontypes.TxMeta{}, testPubKeyHex, aptos.AccountAddress{}, sampleEntryFunction(t), false)
	require.NoError(t, err)

	tx, ok := txm.transactions[id]
	require.True(t, ok)
	assert.Equal(t, derived.String(), tx.FromAddress.String(), "zero fromAddress must derive from pubkey")
}

