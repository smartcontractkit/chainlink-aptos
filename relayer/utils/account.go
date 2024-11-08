package utils

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/aptos-labs/aptos-go-sdk"
)

// HexToEd25519PublicKey converts a hex string to an Ed25519 public key.
func HexToEd25519PublicKey(hexKey string) (ed25519.PublicKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: %d bytes, expected %d bytes", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}

// Ed25519PublicKeyToAccount converts an Ed25519 public key to an Aptos account address.
func Ed25519PublicKeyToAccount(key ed25519.PublicKey) aptos.AccountAddress {
	authKey := sha3.Sum256(append([]byte(key), 0x00 /* account key prefix */))
	return aptos.AccountAddress(authKey)
}

func HexToAccountAddressString(hexKey string) (string, error) {
	publicKey, err := HexToEd25519PublicKey(hexKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert hex to public key: %v", err)
	}

	accountAddress := Ed25519PublicKeyToAccount(publicKey)
	return accountAddress.String(), nil
}
