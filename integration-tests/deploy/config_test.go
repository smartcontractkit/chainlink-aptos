package deploy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"
)

func TestMarshalCoreTomlPreservesLocalCapabilities(t *testing.T) {
	t.Parallel()

	input := `
[Capabilities.Local]
[Capabilities.Local.Capabilities."mock-streams-trigger@1.0.0"]

[WebServer]
HTTPPort = 6688
AllowOrigins = '*'
[WebServer.TLS]
HTTPSPort = 0
`

	var cfg CoreConfigToml
	_, err := toml.Decode(input, &cfg)
	require.NoError(t, err)

	out, err := marshalCoreToml(&cfg)
	require.NoError(t, err)
	require.Contains(t, out, `[Capabilities.Local.Capabilities."mock-streams-trigger@1.0.0"]`)
}

func TestCoreTemplateRoundTripPreservesMockTrigger(t *testing.T) {
	t.Parallel()

	input, err := os.ReadFile(filepath.Join(scripts.Templates, "core.toml"))
	require.NoError(t, err)

	var cfg CoreConfigToml
	_, err = toml.Decode(string(input), &cfg)
	require.NoError(t, err)

	out, err := marshalCoreToml(&cfg)
	require.NoError(t, err)
	require.Contains(t, out, `[Capabilities.Local.Capabilities."mock-streams-trigger@1.0.0"]`)
}
