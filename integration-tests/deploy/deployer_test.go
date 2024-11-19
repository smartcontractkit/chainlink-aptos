package deploy

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestCreateNodesList(t *testing.T) {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	deployer := &Deployer{
		lggr: &logger,
		Keystone: &Keystone{
			NodesList: "test_nodes_list.txt",
		},
		Core: []*CoreClient{
			{
				Name: "core-0",
				Config: &CoreConfig{
					Email:    "test-email-0",
					Password: "test-password-0",
				},
				ExternalPort: 8000,
			},
			{
				Name: "core-1",
				Config: &CoreConfig{
					Email:    "test-email-1",
					Password: "test-password-1",
				},
				ExternalPort: 8001,
			},
		},
	}

	err := deployer.CreateNodesList()
	assert.NoError(t, err)

	nodeList, err := os.ReadFile(deployer.Keystone.NodesList)
	assert.NoError(t, err)
	expectedNodesList := `localhost:8000 core-0:6688 test-email-0 test-password-0
localhost:8001 core-1:6688 test-email-1 test-password-1`
	assert.Equal(t, expectedNodesList, string(nodeList))

	assert.NoError(t, err)

	// Clean up
	os.Remove(deployer.Keystone.NodesList)
}
