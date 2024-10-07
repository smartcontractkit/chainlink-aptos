package forwarder

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	wt_msg "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitoring/pb/write-target"
)

func TestDecodeAsReportProcessed(t *testing.T) {
	// Base64-encoded report data (example)
	// version | workflow_execution_id | timestamp | don_id | config_version | ... | data
	encoded := "AYFtgPpLuLNQysw6LjlSNrzGuBOwVoth7qC9PmunIY3TZvW/cAAAAAEAAAABvAbzAOeX1ahXVjehSq4T4/hQgAjR/FT0xGEf/xemjLAwMDAwRk9PQkFSAAAAAAAAAAAAAAAAAAAAAAAAAKoAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAMREREREREREQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAMREREREREREQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZvW/aQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABm9b9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBQGpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJQlAAMiIiIiIiIiIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAMiIiIiIiIiIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZvW/aQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABm9b9pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABnBQGpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAElCUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASUJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABJQl"

	// Decode the base64 data
	rawReport, err := base64.StdEncoding.DecodeString(encoded)
	require.NoError(t, err)

	// Define test cases
	tests := []struct {
		name     string
		input    wt_msg.WriteConfirmed
		expected ReportProcessed
		wantErr  bool
	}{
		{
			name: "Valid input",
			input: wt_msg.WriteConfirmed{
				Node:      "example-node",
				Forwarder: "example-forwarder",
				Receiver:  "example-receiver",

				// Report Info
				ReportId:      123,
				ReportContext: []byte{},
				Report:        rawReport, // Example valid byte slice
				SignersNum:    2,

				// Transmission Info
				Transmitter: "example-transmitter",
				Success:     true,

				// Block Info
				BlockHash:      "0xaa",
				BlockHeight:    "17",
				BlockTimestamp: 0x66f5bf69,
			},
			expected: ReportProcessed{
				Receiver:            "example-receiver",
				WorkflowExecutionId: []uint8{0x81, 0x6d, 0x80, 0xfa, 0x4b, 0xb8, 0xb3, 0x50, 0xca, 0xcc, 0x3a, 0x2e, 0x39, 0x52, 0x36, 0xbc, 0xc6, 0xb8, 0x13, 0xb0, 0x56, 0x8b, 0x61, 0xee, 0xa0, 0xbd, 0x3e, 0x6b, 0xa7, 0x21, 0x8d, 0xd3},
				ReportId:            123,
				Success:             true,

				BlockHash:      "0xaa",
				BlockHeight:    "17",
				BlockTimestamp: 0x66f5bf69,
			},
			wantErr: false,
		},
		{
			name: "Invalid input",
			input: wt_msg.WriteConfirmed{
				Node:      "example-node",
				Forwarder: "example-forwarder",
				Receiver:  "example-receiver",

				// Report Info
				ReportId:      123,
				ReportContext: []byte{},
				Report:        []byte{0x01, 0x02, 0x03, 0x04}, // Example invalid byte slice
				SignersNum:    2,

				// Transmission Info
				Transmitter: "example-transmitter",
				Success:     true,

				// Block Info
				BlockHash:      "0xaa",
				BlockHeight:    "17",
				BlockTimestamp: 0x66f5bf69,
			},
			expected: ReportProcessed{},
			wantErr:  true,
		},
		// Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeAsReportProcessed(&tt.input)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.expected, *result)
			}
		})
	}
}
