package aptos

import (
	_ "embed"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-aptos/relayer/config"
)

//go:embed CONFIG.md
var configMD string

func TestConfigDocs(t *testing.T) {
	cfg, err := config.GenerateDocs()
	assert.NoError(t, err, "invalid config docs")
	assert.Equal(t, configMD, cfg, "CONFIG.md is out of date. Run 'go generate .' to regenerate.")
}
