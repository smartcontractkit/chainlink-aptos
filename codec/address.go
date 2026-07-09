package codec

import (
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/hex"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
)

func HexPublicKeyToAddress(key string) (string, error) {
	publicKey, err := hexPublicKeyToEd25519PublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to convert hex to public key: %w", err)
	}

	addr := edd25519PublicKeyToAddress(publicKey)
	return addr.String(), nil
}

// hexPublicKeyToEd25519PublicKey converts a hex string to an Ed25519 public key.
func hexPublicKeyToEd25519PublicKey(key string) (ed25519.PublicKey, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: %d bytes, expected %d bytes", len(keyBytes), ed25519.PublicKeySize)
	}

	return keyBytes, nil
}

// edd25519PublicKeyToAddress converts an Ed25519 public key to an Aptos account address.
func edd25519PublicKeyToAddress(key ed25519.PublicKey) aptos.AccountAddress {
	return sha3.Sum256(append(key, 0x00 /* account key prefix */))
}
