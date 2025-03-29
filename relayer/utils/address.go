package utils

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"

	"github.com/aptos-labs/aptos-go-sdk"
)

// HexPublicKeyToEd25519PublicKey converts a hex string to an Ed25519 public key.
func HexPublicKeyToEd25519PublicKey(key string) (ed25519.PublicKey, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: %d bytes, expected %d bytes", len(keyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(keyBytes), nil
}

// Ed25519PublicKeyToAddress converts an Ed25519 public key to an Aptos account address.
func Ed25519PublicKeyToAddress(key ed25519.PublicKey) aptos.AccountAddress {
	authKey := sha3.Sum256(append([]byte(key), 0x00 /* account key prefix */))
	return aptos.AccountAddress(authKey)
}

func HexPublicKeyToAddress(key string) (aptos.AccountAddress, error) {
	publicKey, err := HexPublicKeyToEd25519PublicKey(key)
	if err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("failed to convert hex to public key: %v", err)
	}

	accountAddress := Ed25519PublicKeyToAddress(publicKey)
	return accountAddress, nil
}

func HexPublicKeyToAddressString(key string) (string, error) {
	publicKey, err := HexPublicKeyToEd25519PublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to convert hex to public key: %v", err)
	}

	accountAddress := Ed25519PublicKeyToAddress(publicKey)
	return accountAddress.String(), nil
}

// HexAddressToAddress converts a hex string to an Aptos account address.
// Notice: will force [32]byte hex decoding for canonical address representation
func HexAddressToAddress(addr string) (aptos.AccountAddress, error) {
	var address aptos.AccountAddress
	if err := address.ParseStringRelaxed(addr); err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("failed to parse account address: %v", err)
	}
	return address, nil
}

func PublicKeyBytesToAddress(publicKey []byte) (aptos.AccountAddress, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return aptos.AccountAddress{}, fmt.Errorf("invalid key length: %d bytes, expected %d bytes", len(publicKey), ed25519.PublicKeySize)
	}

	return Ed25519PublicKeyToAddress(ed25519.PublicKey(publicKey)), nil
}
