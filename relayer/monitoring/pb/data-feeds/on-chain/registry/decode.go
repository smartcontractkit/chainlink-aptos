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
				// Notice: we publish DataFeed FeedID, not the unrelying DataStream FeedID
				FeedId:                rf.FeedId[:], // Convert [32]byte to []byte
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
				// Notice: we publish DataFeed FeedID, not the unrelying DataStream FeedID
				FeedId:                rf.FeedId[:], // Convert [32]byte to []byte
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

// FeedID represents a 32-byte feed ID
type FeedID [32]byte

// GetReportType returns the report type sourced from the feedId
//
// [DF2.0 | Data ID Final Specification](https://docs.google.com/document/d/13ciwTx8lSUfyz1IdETwpxlIVSn1lwYzGtzOBBTpl5Vg/edit?usp=sharing)
// Byte 0: ID Format - 256 options (base case)
//   - Incrementing from 0
//   - 0x00 = current Data Streams format
//   - 0x01 = this format
//   - 0x02 = PoR self-serve SA team allocated IDs (15 bytes)
//   - 0x03 = PoR from feeds team
//   - 0xFF can extend ID format to subsequent bytes, so 0xFF00 is first, then 0xFF01, etc.
func (id FeedID) GetReportType() uint8 {
	// Get the first byte of the feedId
	return id[0]
}

// GetDecimals returns the number of decimals for the feed, derived from the feedId
//
// [DF2.0 | Data ID Final Specification](https://docs.google.com/document/d/13ciwTx8lSUfyz1IdETwpxlIVSn1lwYzGtzOBBTpl5Vg/edit?usp=sharing)
// Byte 7: Data Type - 256 options
//   - Given the variety of buckets, a data type for the buckets will be useful for correct parsing
//   - 0x00 = Boolean
//   - 0x01= String
//   - 0x02 = Address
//   - 0x03 = Bytes
//   - 0x04 = Bundle (Encoded Struct)
//   - 0x05-0x1F reserved
//   - 0x20 = Decimal0 (Integer)
//   - 0x21 = Decimal1 (Float w/ 1 decimal place)
//   - …
//   - 0x28 = Decimal8
//   - …
//   - 0x32 = Decimal18
//   - …
//   - 0x60 = Decimal64
//   - 0x61-0xFF reserved
func (id FeedID) GetDataType() uint8 {
	// Get the 8th byte (index 7) of the feedId
	return id[7]
}

// GetDecimals returns the number of decimals for the fe7], derived from the data type
// Returns false if the data type is not a number
func GetDecimals(dataType uint8) (uint8, bool) {
	if dataType >= 0x20 && dataType <= 0x60 {
		return dataType - 0x20, true
	}
	// Else if the data type is not a number
	return 0, false
}
