package common

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

// mirrored from https://github.com/smartcontractkit/chainlink/blob/e9e885cb2dc08d24dc115587a1cab96eae38d779/integration-tests/deployment/keystone/ocr3config.go#L53
type NodeKeys struct {
	EthAddress            string `json:"EthAddress"`
	AptosAccount          string `json:"AptosAccount"`
	AptosBundleID         string `json:"AptosBundleID"`
	AptosOnchainPublicKey string `json:"AptosOnchainPublicKey"`
	P2PPeerID             string `json:"P2PPeerID"`             // p2p_<key>
	OCR2BundleID          string `json:"OCR2BundleID"`          // used only in job spec
	OCR2OnchainPublicKey  string `json:"OCR2OnchainPublicKey"`  // ocr2on_evm_<key>
	OCR2OffchainPublicKey string `json:"OCR2OffchainPublicKey"` // ocr2off_evm_<key>
	OCR2ConfigPublicKey   string `json:"OCR2ConfigPublicKey"`   // ocr2cfg_evm_<key>
	CSAPublicKey          string `json:"CSAPublicKey"`
	EncryptionPublicKey   string `json:"EncryptionPublicKey"`
}

func LoadPublicKeys(fileLocation string, logger zerolog.Logger) ([]NodeKeys, error) {
	file, err := os.Open(fileLocation)
	if err != nil {
		return []NodeKeys{}, err
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return []NodeKeys{}, err
	}

	var accounts []NodeKeys
	if err := json.Unmarshal(fileContent, &accounts); err != nil {
		return []NodeKeys{}, err
	}

	return accounts, nil
}

func GenerateWorkflowToml(dataFeedsAddress string, workflowOwner string) string {
	defaultToml := `
type = "workflow"
schemaVersion = 1
name = "aptosfeed1"
forwardingAllowed = false
workflow = """
name: "0000FOOBAR"
owner: "%s"
triggers:
 - id: "mock-streams-trigger@1.0.0"
   config:
     maxFrequencyMs: 5000
     feedIds:
       - "0x0003111111111111111100000000000000000000000000000000000000000000"
       - "0x0003222222222222222200000000000000000000000000000000000000000000"

consensus:
 - id: "offchain_reporting@1.0.0"
   ref: "aptos_feeds"
   inputs:
     observations:
       - "$(trigger.outputs)"
   config:
     report_id: "0001"
     key_id: "aptos"
     aggregation_method: "data_feeds"
     aggregation_config:
       allowedPartialStaleness: "0.5"
       feeds:
         "0x0003111111111111111100000000000000000000000000000000000000000000":
           deviation: "0.05"
           heartbeat: 60
         "0x0003222222222222222200000000000000000000000000000000000000000000":
           deviation: "0.05"
           heartbeat: 60
     encoder: "EVM"
     encoder_config:
       abi: "(bytes32 FeedID, bytes RawReport)[] Reports"
targets:
 - id: "write_aptos-localnet@1.0.0"
   inputs:
     signed_report: "$(aptos_feeds.outputs)" # TODO: annotate with network if not shared across networks
   config:
     address: "%s"
     deltaStage: "45s"
     schedule: "oneAtATime"
"""`
	return fmt.Sprintf(defaultToml, workflowOwner, dataFeedsAddress)
}
