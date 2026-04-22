package transmitter

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

// Config is the [Aptos.Transmitter] TOML section.
type Config struct {
	// Overrides maps a hex-encoded ed25519 public key (as reported by
	// `chainlink keys aptos list`) to the on-chain account address to
	// use as the transaction sender. Unlisted keys fall back to the
	// standard Aptos derivation.
	Overrides map[string]string `toml:"Overrides"`
}

// ValidateConfig rejects malformed entries and semantic duplicates
// (distinct TOML keys that resolve to the same lookup key).
func (c *Config) ValidateConfig() error {
	if c == nil {
		return nil
	}
	seen := make(map[string]string, len(c.Overrides))
	for pk, addr := range c.Overrides {
		norm, err := normalizePublicKey(pk)
		if err != nil {
			return fmt.Errorf("Transmitter.Overrides key %q: %w", pk, err)
		}
		if prev, dup := seen[norm]; dup {
			return fmt.Errorf("Transmitter.Overrides: keys %q and %q normalize to the same public key", prev, pk)
		}
		seen[norm] = pk

		var a aptos.AccountAddress
		if err := a.ParseStringRelaxed(addr); err != nil {
			return fmt.Errorf("Transmitter.Overrides[%q] = %q: %w", pk, addr, err)
		}
	}
	return nil
}

// ResolveAddress returns the override address registered for publicKey
// if one exists, else derives the address from the public key.
func (c *Config) ResolveAddress(publicKey string) (aptos.AccountAddress, error) {
	if c != nil && len(c.Overrides) > 0 {
		want, err := normalizePublicKey(publicKey)
		if err != nil {
			return aptos.AccountAddress{}, fmt.Errorf("invalid public key %q: %w", publicKey, err)
		}
		for k, v := range c.Overrides {
			got, err := normalizePublicKey(k)
			if err != nil {
				continue // already rejected by ValidateConfig
			}
			if got == want {
				var addr aptos.AccountAddress
				if err := addr.ParseStringRelaxed(v); err != nil {
					return aptos.AccountAddress{}, fmt.Errorf("invalid Transmitter.Overrides[%q] address %q: %w", k, v, err)
				}
				return addr, nil
			}
		}
	}
	return utils.HexPublicKeyToAddress(publicKey)
}

func normalizePublicKey(pk string) (string, error) {
	pk = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(pk), "0x"))
	if _, err := hex.DecodeString(pk); err != nil {
		return "", fmt.Errorf("not valid hex: %w", err)
	}
	if _, err := utils.HexPublicKeyToEd25519PublicKey(pk); err != nil {
		return "", err
	}
	return pk, nil
}
