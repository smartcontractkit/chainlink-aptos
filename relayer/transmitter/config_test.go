package transmitter

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

const (
	// Two real ed25519 public keys (32 bytes each) for use in tests.
	pubKeyA = "abababababababababababababababababababababababababababababababab"
	pubKeyB = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

	rotatedAddrA = "0x1111111111111111111111111111111111111111111111111111111111111111"
	rotatedAddrB = "0x2222222222222222222222222222222222222222222222222222222222222222"
)

func TestConfig_ValidateConfig(t *testing.T) {
	t.Run("nil receiver", func(t *testing.T) {
		var c *Config
		require.NoError(t, c.ValidateConfig())
	})

	t.Run("empty overrides", func(t *testing.T) {
		c := &Config{}
		require.NoError(t, c.ValidateConfig())
	})

	t.Run("valid entries", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{
			pubKeyA:        rotatedAddrA,
			"0x" + pubKeyB: rotatedAddrB,
		}}
		require.NoError(t, c.ValidateConfig())
	})

	t.Run("public key not hex", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{"zz": rotatedAddrA}}
		err := c.ValidateConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Transmitter.Overrides key")
	})

	t.Run("public key wrong length", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{"abcd": rotatedAddrA}}
		err := c.ValidateConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Transmitter.Overrides key")
	})

	t.Run("semantic duplicate keys rejected", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{
			pubKeyA:        rotatedAddrA,
			"0x" + pubKeyA: rotatedAddrB,
		}}
		err := c.ValidateConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "normalize to the same public key")
	})

	t.Run("address invalid", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{pubKeyA: "not-an-address"}}
		err := c.ValidateConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Transmitter.Overrides")
	})
}

func TestConfig_ResolveAddress(t *testing.T) {
	derivedA, err := utils.HexPublicKeyToAddress(pubKeyA)
	require.NoError(t, err)

	t.Run("nil receiver derives", func(t *testing.T) {
		var c *Config
		got, err := c.ResolveAddress(pubKeyA)
		require.NoError(t, err)
		assert.Equal(t, derivedA.String(), got.String())
	})

	t.Run("no overrides derives", func(t *testing.T) {
		c := &Config{}
		got, err := c.ResolveAddress(pubKeyA)
		require.NoError(t, err)
		assert.Equal(t, derivedA.String(), got.String())
	})

	t.Run("matching override returns override", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{pubKeyA: rotatedAddrA}}
		got, err := c.ResolveAddress(pubKeyA)
		require.NoError(t, err)
		assert.Equal(t, strings.ToLower(rotatedAddrA), strings.ToLower(got.String()))
	})

	t.Run("non-matching pubkey derives", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{pubKeyA: rotatedAddrA}}
		derivedB, err := utils.HexPublicKeyToAddress(pubKeyB)
		require.NoError(t, err)
		got, err := c.ResolveAddress(pubKeyB)
		require.NoError(t, err)
		assert.Equal(t, derivedB.String(), got.String())
	})

	t.Run("normalization: 0x prefix on either side", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{"0x" + pubKeyA: rotatedAddrA}}
		got, err := c.ResolveAddress(pubKeyA) // no prefix on lookup
		require.NoError(t, err)
		assert.Equal(t, strings.ToLower(rotatedAddrA), strings.ToLower(got.String()))
	})

	t.Run("normalization: trims surrounding whitespace", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{"  " + pubKeyA + "\t": rotatedAddrA}}
		got, err := c.ResolveAddress("\t" + pubKeyA + " ")
		require.NoError(t, err)
		assert.Equal(t, strings.ToLower(rotatedAddrA), strings.ToLower(got.String()))
	})

	t.Run("normalization: case-insensitive", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{strings.ToUpper(pubKeyA): rotatedAddrA}}
		got, err := c.ResolveAddress(pubKeyA)
		require.NoError(t, err)
		assert.Equal(t, strings.ToLower(rotatedAddrA), strings.ToLower(got.String()))
	})

	t.Run("multiple overrides resolve independently", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{
			pubKeyA: rotatedAddrA,
			pubKeyB: rotatedAddrB,
		}}
		gotA, err := c.ResolveAddress(pubKeyA)
		require.NoError(t, err)
		gotB, err := c.ResolveAddress(pubKeyB)
		require.NoError(t, err)
		assert.NotEqual(t, gotA.String(), gotB.String())
		assert.Equal(t, strings.ToLower(rotatedAddrA), strings.ToLower(gotA.String()))
		assert.Equal(t, strings.ToLower(rotatedAddrB), strings.ToLower(gotB.String()))
	})

	t.Run("invalid lookup pubkey errors", func(t *testing.T) {
		c := &Config{Overrides: map[string]string{pubKeyA: rotatedAddrA}}
		_, err := c.ResolveAddress("not-hex")
		require.Error(t, err)
	})
}
