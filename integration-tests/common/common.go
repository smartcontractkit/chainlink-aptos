package common

import (
	"fmt"
)

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
