package deploy

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestCreateNodeLists(t *testing.T) {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()
	deployer := &Deployer{
		lggr: &logger,
		Keystone: &Keystone{
			LocalNodeList: "test_local_node_list.txt",
			NodeList:      "test_node_list.txt",
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

	err := deployer.CreateNodeLists()
	assert.NoError(t, err)

	localNodeList, err := os.ReadFile(deployer.Keystone.LocalNodeList)
	assert.NoError(t, err)
	expectedLocalNodeList := `localhost:8000 core-0:6688 test-email-0 test-password-0
localhost:8001 core-1:6688 test-email-1 test-password-1`
	assert.Equal(t, expectedLocalNodeList, string(localNodeList))

	externalNodeList, err := os.ReadFile(deployer.Keystone.NodeList)
	assert.NoError(t, err)
	expectedExternalNodeList := `core-0:8000 test-email-0 test-password-0
core-1:8001 test-email-1 test-password-1`
	assert.Equal(t, expectedExternalNodeList, string(externalNodeList))

	// Clean up
	os.Remove(deployer.Keystone.LocalNodeList)
	os.Remove(deployer.Keystone.NodeList)
}
