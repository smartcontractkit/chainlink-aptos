package deploy

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/smartcontractkit/chainlink-aptos/integration-tests/scripts"

	keystone "github.com/smartcontractkit/chainlink/core/scripts/keystone/src"
)

type Keystone struct {
	NodesList    string
	ArtefactsDir string
	ChainId      string
	GethHttpRPC  string
	P2PPort      int
}

func (k *Keystone) FetchNodeKeys() ([]keystone.NodeKeys, error) {
	keystone.NewToolkit().Run([]string{
		"get-aptos-keys",
		fmt.Sprintf("--nodes=%s", k.NodesList),
		fmt.Sprintf("--chainid=%s", k.ChainId),
		fmt.Sprintf("--artefacts=%s", k.ArtefactsDir),
	})

	file, err := os.Open(k.ArtefactsDir + "/pubnodekeys.json")
	if err != nil {
		return []keystone.NodeKeys{}, err
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return []keystone.NodeKeys{}, err
	}

	var accounts []keystone.NodeKeys
	if err := json.Unmarshal(fileContent, &accounts); err != nil {
		return []keystone.NodeKeys{}, err
	}

	return accounts, nil
}

// Deploy OCR3 contracts
func (k *Keystone) DeployOCR3Contracts(gethPrivKey string) {
	keystone.NewToolkit().Run([]string{
		"deploy-ocr3-contracts",
		fmt.Sprintf("--ethurl=%s", k.GethHttpRPC),
		fmt.Sprintf("--accountkey=%s", gethPrivKey),
		fmt.Sprintf("--chainid=%s", k.ChainId),
		fmt.Sprintf("--nodes=%s", k.NodesList),
		fmt.Sprintf("--artefacts=%s", k.ArtefactsDir),
		fmt.Sprintf("--ocrfile=%s/%s", scripts.Templates, "ocr_config.json"),
	})
}

func (k *Keystone) DeployOCR3JobSpecs(gethPrivKey string) {
	keystone.NewToolkit().Run([]string{
		"deploy-ocr3-jobspecs",
		fmt.Sprintf("--ethurl=%s", k.GethHttpRPC),
		fmt.Sprintf("--accountkey=%s", gethPrivKey),
		fmt.Sprintf("--chainid=%s", k.ChainId),
		fmt.Sprintf("--nodes=%s", k.NodesList),
		fmt.Sprintf("--p2pport=%d", k.P2PPort),
		fmt.Sprintf("--artefacts=%s", k.ArtefactsDir),
	})
}

func (k *Keystone) DeployWorkflows(workflowFile string) {
	keystone.NewToolkit().Run([]string{
		"deploy-workflows",
		fmt.Sprintf("--workflow=%s", workflowFile),
		fmt.Sprintf("--nodes=%s", k.NodesList),
	})
}
