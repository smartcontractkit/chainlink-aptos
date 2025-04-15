package testutils

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

// Loads an account, assuming no key rotation has taken place.
func LoadAccountFromEnv(t *testing.T, logger logger.Logger) (ed25519.PrivateKey, ed25519.PublicKey, aptos.AccountAddress) {
	privateKeyHex := os.Getenv("PRIVATE_KEY")
	if privateKeyHex == "" {
		return nil, nil, aptos.AccountAddress{}
	}

	if privateKeyHex[0:2] == "0x" {
		privateKeyHex = privateKeyHex[2:]
	}

	if len(privateKeyHex) != 128 {
		t.Fatalf("PRIVATE_KEY must be a hex string of length 128, representing a 64-byte ed25519 key (private key + public key)")
	}

	privateKeyBytes, err := utils.DecodeHexRelaxed(privateKeyHex)
	require.NoError(t, err)
	privateKey := ed25519.PrivateKey(privateKeyBytes)

	// TODO: using ed25519.PrivateKey.Public() returns a `crypto.PublicKey` which is a typed `any`, and
	// []byte(publicKey) and publicKey.([]byte) don't seem to work. there's probably a better way to do this?
	// copied from https://cs.opensource.google/go/go/+/refs/tags/go1.22.3:src/crypto/ed25519/ed25519.go;l=57
	publicKeyBytes := make([]byte, ed25519.PublicKeySize)
	copy(publicKeyBytes, []byte(privateKey)[32:])
	publicKey := ed25519.PublicKey(publicKeyBytes)

	authKey := sha3.Sum256(append(publicKeyBytes, 0x00))
	accountAddress := aptos.AccountAddress(authKey)

	logger.Debugw("Loaded account", "publicKey", hex.EncodeToString(publicKeyBytes), "address", accountAddress.String())

	return privateKey, publicKey, accountAddress
}
