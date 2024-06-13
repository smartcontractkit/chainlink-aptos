package testutils

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/loop"
)

type TestKeystore struct {
	t          *testing.T
	address    string
	privateKey ed25519.PrivateKey
}

var _ loop.Keystore = &TestKeystore{}

func NewTestKeystore(t *testing.T, address string, privateKey ed25519.PrivateKey) *TestKeystore {
	return &TestKeystore{t: t, address: address, privateKey: privateKey}
}

func (tk *TestKeystore) Sign(ctx context.Context, id string, hash []byte) ([]byte, error) {
	require.Equal(tk.t, tk.address, id)

	// used to check if the account exists.
	if hash == nil {
		return nil, nil
	}

	return ed25519.Sign(tk.privateKey, hash), nil
}

func (tk *TestKeystore) Accounts(ctx context.Context) ([]string, error) {
	return []string{tk.address}, nil
}
