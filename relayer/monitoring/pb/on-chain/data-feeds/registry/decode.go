package registry

import (
	"fmt"

	wt_msg "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/data_feeds"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/keystone"

	mercury_vX "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/common"
	mercury_v3 "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/v3"
	mercury_v4 "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/report/mercury/v4"
)

// DecodeAsFeedUpdated decodes a 'write-target.WriteConfirmed' message
// as a 'data-feeds.registry.ReportProcessed' message
func DecodeAsFeedUpdated(m *wt_msg.WriteConfirmed) ([]*FeedUpdated, error) {
	// Decode the confirmed report (WT -> Keystone forwarder)
	r, err := keystone.Decode(m.Report)
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
				FeedId:    rm.FeedId[:], // Convert [32]byte to []byte
				Timestamp: rm.ObservationsTimestamp,
				// TODO: u256 lossy conversion
				Benchmark: rm.BenchmarkPrice.Uint64(), // Map big.Int as uint64
				Report:    rf.Data,

				// Notice: we skip head/tx data here (unknown), as we map from 'write-target.WriteConfirmed'
				// and not from tx/event data (e.g., 'write-target.WriteTxConfirmed')

				BlockHash:      m.BlockHash,
				BlockHeight:    m.BlockHeight,
				BlockTimestamp: m.BlockTimestamp,
			})
		case uint16(4):
			rm, err := mercury_v4.Decode(rf.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to decode Mercury v%d report: %w", t, err)
			}

			msgs = append(msgs, &FeedUpdated{
				// Event data
				FeedId:    rm.FeedId[:], // Convert [32]byte to []byte
				Timestamp: rm.ObservationsTimestamp,
				// TODO: u256 lossy conversion
				Benchmark: rm.BenchmarkPrice.Uint64(), // Map big.Int as uint64
				Report:    rf.Data,

				// Notice: we skip head/tx data here (unknown), as we map from 'write-target.WriteConfirmed'
				// and not from tx/event data (e.g., 'write-target.WriteTxConfirmed')

				BlockHash:      m.BlockHash,
				BlockHeight:    m.BlockHeight,
				BlockTimestamp: m.BlockTimestamp,
			})
		default:
			return nil, fmt.Errorf("unsupported Mercury report type: %d", t)
		}
	}

	return msgs, nil
}
