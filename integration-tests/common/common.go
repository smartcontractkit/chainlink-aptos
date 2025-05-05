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
       - "1020001001" # BTC / USD
       - "1020000101" # ETH / USD
       - "1020000102" # LINK / USD

consensus:
  - id: "offchain_reporting@1.0.0"
    ref: "data-feeds"
    inputs:
      observations:
        - $(trigger.outputs)
    config:
      report_id: "0002"
      key_id: "evm"
      aggregation_method: "llo_streams"
      aggregation_config:
        streams:
          "1020001001": # BTC / USD
            remappedID: "0x01bb0467f5000304000000000000000000000000000000000000000000000000"
            deviation: "0.05"
            heartbeat: 1800
          "1020000101": # ETH / USD
            remappedID: "0x01d585327c000332000000000000000000000000000000000000000000000000"
            deviation: "0.05"
            heartbeat: 1800
          "1020000102": # LINK / USD
            remappedID: "0x0101199b3b000332000000000000000000000000000000000000000000000000"
            deviation: "0.05"
            heartbeat: 1800

      encoder: "EVM"
      encoder_config:
        abi: (bytes32 RemappedID, uint32 Timestamp, uint224 Price)[] Reports
targets:
 - id: "write_aptos-localnet@1.0.0"
   inputs:
     signed_report: "$(data-feeds.outputs)" # TODO: annotate with network if not shared across networks
   config:
     address: "%s"
     deltaStage: "45s"
     schedule: "oneAtATime"
"""`
	return fmt.Sprintf(defaultToml, workflowOwner, dataFeedsAddress)
}
