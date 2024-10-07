package deploy

import (
	"fmt"
	"integration-tests/scripts"

	functions "github.com/smartcontractkit/chainlink/core/scripts/functions/src"
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

func (k *Keystone) FetchKeys() {
	functions.NewFetchKeysCommand().Run([]string{fmt.Sprintf("--output=%s", k.PublicKeys), "-nodes", k.LocalNodeList, "--chainid", k.ChainId})
}

func (k *Keystone) DeployContracts(gethPrivKey string) {
	keystone.NewDeployContractsCommand().Run([]string{fmt.Sprintf("--artefacts=%s", k.ArtefactsDir), fmt.Sprintf("--nodes=%s", k.LocalNodeList), fmt.Sprintf("--publickeys=%s", k.PublicKeys), "--ocrfile", fmt.Sprintf("%s/%s", scripts.Templates, "ocr_config.json"), "--chainid", k.ChainId, fmt.Sprintf("--ethurl=%s", k.GethHttpRPC), fmt.Sprintf("--accountkey=%s", gethPrivKey)})
}

func (k *Keystone) DeployJobSpecs() {
	keystone.NewDeployJobSpecsCommand().Run([]string{fmt.Sprintf("--templates=%s", scripts.Templates), fmt.Sprintf("--nodes=%s", k.LocalNodeList), fmt.Sprintf("--publickeys=%s", k.PublicKeys), fmt.Sprintf("--artefacts=%s", k.ArtefactsDir), fmt.Sprintf("--chainid=%s", k.ChainId), fmt.Sprintf("--p2pport=%d", k.P2PPort)})
}

func (k *Keystone) DeployWorkflows(workflowFile string) {
	keystone.NewDeployWorkflowsCommand().Run([]string{fmt.Sprintf("--workflow=%s", workflowFile), fmt.Sprintf("--nodes=%s", k.LocalNodeList)})
}

func (k *Keystone) DeleteWorkflows() {
	keystone.NewDeleteWorkflowsCommand().Run([]string{fmt.Sprintf("--nodes=%s", k.LocalNodeList)})
}

func (k *Keystone) DeleteJobSpecs() {
	keystone.NewDeleteJobsCommand().Run([]string{fmt.Sprintf("--nodes=%s", k.LocalNodeList), fmt.Sprintf("--artefacts=%s", k.ArtefactsDir)})
}
