package deploy

import (
	"fmt"
	"integration-tests/scripts"

	keystone "github.com/smartcontractkit/chainlink/core/scripts/keystone/src"
)

type Keystone struct {
	NodeList      string
	LocalNodeList string
	PublicKeys    string
	ArtefactsDir  string
	ChainId       string
	GethHttpRPC   string
	P2PPort       int
}

// Deploy OCR3 contracts
func (k *Keystone) DeployOCR3Contracts(gethPrivKey string) {
	keystone.NewToolkit().Run([]string{
		"deploy-ocr3-contracts",
		fmt.Sprintf("--ethurl=%s", k.GethHttpRPC),
		fmt.Sprintf("--accountkey=%s", gethPrivKey),
		fmt.Sprintf("--chainid=%s", k.ChainId),
		fmt.Sprintf("--nodes=%s", k.LocalNodeList),
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
		fmt.Sprintf("--nodes=%s", k.LocalNodeList),
		fmt.Sprintf("--p2pport=%d", k.P2PPort),
		fmt.Sprintf("--artefacts=%s", k.ArtefactsDir),
	})
}

func (k *Keystone) DeployWorkflows(workflowFile string) {
	keystone.NewToolkit().Run([]string{
		"deploy-workflows",
		fmt.Sprintf("--workflow=%s", workflowFile),
		fmt.Sprintf("--nodes=%s", k.LocalNodeList),
	})
}
