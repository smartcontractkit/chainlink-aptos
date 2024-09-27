package data_feeds

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/product/mercury"
	wt "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/write_target"
)

func TestDecodeReport(t *testing.T) {
	// Base64-encoded report data (example)
	// version | workflow_execution_id | timestamp | don_id | config_version | ... | data
	encoded := "AYFtgPpLuLNQysw6LjlSNrzGuBOwVoth7qC9PmunIY3TZvW/cAAAAAEAAAABvAbzAOeX1ahXVjehSq4T4/hQgAjR/FT0xGEf/xemjLAwMDAwRk9PQkFSAAAAAAAAAAAAAAAAAAAAAAAAAKoAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAMREREREREREQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAMREREREREREQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZvW/aQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABm9b9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBQGpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJQlAAMiIiIiIiIiIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAMiIiIiIiIiIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZvW/aQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABm9b9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBQGpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJQl"

	// Decode the base64 data
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Decode the report
	report, err := wt.Decode(decoded)
	require.NoError(t, err)
	t.Log(fmt.Sprintf("Decoded as report: %+v", report))

	expectedFeedID := []string{
		"0003111111111111111100000000000000000000000000000000000000000000",
		"0003222222222222222200000000000000000000000000000000000000000000",
	}

	expectedData := []mercury.Report{
		mercury.Report{
			FeedId:                [32]uint8{0x0, 0x3, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			ObservationsTimestamp: 0x66f5bf69,
			BenchmarkPrice:        big.NewInt(300069),
			Bid:                   big.NewInt(300069),
			Ask:                   big.NewInt(300069),
			ValidFromTimestamp:    0x66f5bf69,
			ExpiresAt:             0x670501a9,
			LinkFee:               big.NewInt(300069),
			NativeFee:             big.NewInt(300069),
		},
		mercury.Report{
			FeedId:                [32]uint8{0x0, 0x3, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			ObservationsTimestamp: 0x66f5bf69,
			BenchmarkPrice:        big.NewInt(300069),
			Bid:                   big.NewInt(300069),
			Ask:                   big.NewInt(300069),
			ValidFromTimestamp:    0x66f5bf69,
			ExpiresAt:             0x670501a9,
			LinkFee:               big.NewInt(300069),
			NativeFee:             big.NewInt(300069),
		},
	}

	rDataFeeds := Decode(report.Data)
	require.Equal(t, len(expectedFeedID), len(rDataFeeds.Reports))

	for i, report := range rDataFeeds.Reports {
		require.Equal(t, expectedFeedID[i], report.FeedID)
		require.True(t, len(report.Data) > 0)

		m, err := mercury.Decode(report.Data)
		require.NoError(t, err)
		require.Equal(t, expectedData[i], *m)
	}
}
