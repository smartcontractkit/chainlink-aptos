package contracts

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmbeddedContracts(t *testing.T) {
	t.Parallel()
	// This test checks that all embedded contracts do actually exist by iterating over them and checking that at Move.toml file exists
	for p, s := range Contracts {
		path := filepath.Join(s, "Move.toml")
		_, err := Embed.Open(path)
		require.NoError(t, err, "Failed to open embedded contract", "contract", p, "path", path)
	}
}
