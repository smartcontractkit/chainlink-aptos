package registry

import (
	"fmt"
	"math"
	"math/big"

	wt_msg "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/platform/write-target"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/data_feeds"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/platform"

	mercury_vX "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/common"
	mercury_v3 "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/v3"
	mercury_v4 "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/v4"
)

// DecodeAsFeedUpdated decodes a 'platform.write-target.WriteConfirmed' message
// as a 'data-feeds.registry.ReportProcessed' message
func DecodeAsFeedUpdated(m *wt_msg.WriteConfirmed) ([]*FeedUpdated, error) {
	// Decode the confirmed report (WT -> DF contract event)
	r, err := platform.Decode(m.Report)
	if err != nil {
		return nil, fmt.Errorf("failed to decode report: %w", err)
	}

	// Decode the underlying Data Feeds reports
	reports, err := data_feeds.Decode(r.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Data Feeds report: %w", err)
	}

	// Allocate space for the messages (event per updated feed)
	msgs := make([]*FeedUpdated, 0, len(*reports))

	// Iterate over the underlying Mercury reports
	for _, rf := range *reports {
		// Decode the common Mercury report
		rm, err := mercury_vX.Decode(rf.Data)
		if err != nil {
			return nil, fmt.Errorf("failed to decode Mercury report: %w", err)
		}

		// Parse the report type
		t := mercury_vX.GetReportType(rm.FeedId)
		switch t {
		case uint16(3):
			rm, err := mercury_v3.Decode(rf.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Mercury v%d report: %w", t, err)
			}

			msgs = append(msgs, &FeedUpdated{
				// Event data
				FeedId:                rm.FeedId[:], // Convert [32]byte to []byte
				ObservationsTimestamp: rm.ObservationsTimestamp,
				Benchmark:             rm.BenchmarkPrice.Bytes(), // Map big.Int as []byte
				Report:                rf.Data,

				// Notice: i192 will not fit if number bigger than 64 bits
				BenchmarkVal: toInt64(rm.BenchmarkPrice),

				// Notice: we skip head/tx data here (unknown), as we map from 'platform.write-target.WriteConfirmed'
				// and not from tx/event data (e.g., 'platform.write-target.WriteTxConfirmed')

				BlockHash:      m.BlockHash,
				BlockHeight:    m.BlockHeight,
				BlockTimestamp: m.BlockTimestamp,

				// Execution Context - Chain
				MetaChainName:      m.MetaChainName,
				MetaNetworkName:    m.MetaNetworkName,
				MetaNetworkChainId: m.MetaNetworkChainId,

				// Execution Context - Workflow (capabilities.RequestMetadata)
				MetaWorkflowId:               m.MetaWorkflowId,
				MetaWorkflowOwner:            m.MetaWorkflowOwner,
				MetaWorkflowExecutionId:      m.MetaWorkflowExecutionId,
				MetaWorkflowName:             m.MetaWorkflowName,
				MetaWorkflowDonId:            m.MetaWorkflowDonId,
				MetaWorkflowDonConfigVersion: m.MetaWorkflowDonConfigVersion,
				MetaReferenceId:              m.MetaReferenceId,

				// Execution Context - Capability
				MetaCapabilityType: m.MetaCapabilityType,
				MetaCapabilityId:   m.MetaCapabilityId,
			})
		case uint16(4):
			rm, err := mercury_v4.Decode(rf.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Mercury v%d report: %w", t, err)
			}

			msgs = append(msgs, &FeedUpdated{
				// Event data
				FeedId:                rm.FeedId[:], // Convert [32]byte to []byte
				ObservationsTimestamp: rm.ObservationsTimestamp,
				Benchmark:             rm.BenchmarkPrice.Bytes(), // Map big.Int as []byte
				Report:                rf.Data,

				// Notice: i192 will not fit if number bigger than 64 bits
				BenchmarkVal: toInt64(rm.BenchmarkPrice),

				// Notice: we skip head/tx data here (unknown), as we map from 'platform.write-target.WriteConfirmed'
				// and not from tx/event data (e.g., 'platform.write-target.WriteTxConfirmed')

				BlockHash:      m.BlockHash,
				BlockHeight:    m.BlockHeight,
				BlockTimestamp: m.BlockTimestamp,

				// Execution Context - Chain
				MetaChainName:      m.MetaChainName,
				MetaNetworkName:    m.MetaNetworkName,
				MetaNetworkChainId: m.MetaNetworkChainId,

				// Execution Context - Workflow (capabilities.RequestMetadata)
				MetaWorkflowId:               m.MetaWorkflowId,
				MetaWorkflowOwner:            m.MetaWorkflowOwner,
				MetaWorkflowExecutionId:      m.MetaWorkflowExecutionId,
				MetaWorkflowName:             m.MetaWorkflowName,
				MetaWorkflowDonId:            m.MetaWorkflowDonId,
				MetaWorkflowDonConfigVersion: m.MetaWorkflowDonConfigVersion,
				MetaReferenceId:              m.MetaReferenceId,

				// Execution Context - Capability
				MetaCapabilityType: m.MetaCapabilityType,
				MetaCapabilityId:   m.MetaCapabilityId,
			})
		default:
			return nil, fmt.Errorf("unsupported Mercury report type: %d", t)
		}
	}

	return msgs, nil
}

// toInt64 converts a big.Int to int64
// Returns a math.MinInt64 number that represents an error on overflow.
// This is used to represent and detect huge i192 on-chain values that cannot be represented as int64.
func toInt64(i *big.Int) int64 {
	if i.IsInt64() {
		return i.Int64()
	}
	// Return a number that represents an error (overflow)
	return math.MinInt64 // -1 << 63 = -9223372036854775808
}
