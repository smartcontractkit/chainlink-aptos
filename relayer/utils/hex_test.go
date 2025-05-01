package utils

import (
	"bytes"
	"testing"
)

func TestDecodeHexRelaxed(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "0x prefix",
			input:    "0x1234",
			expected: []byte{0x12, 0x34},
			wantErr:  false,
		},
		{
			name:     "No prefix",
			input:    "1234",
			expected: []byte{0x12, 0x34},
			wantErr:  false,
		},
		{
			name:     "Odd length",
			input:    "123",
			expected: []byte{0x01, 0x23},
			wantErr:  false,
		},
		{
			name:     "Odd length with 0x prefix",
			input:    "0x123",
			expected: []byte{0x01, 0x23},
			wantErr:  false,
		},
		{
			name:     "Single character",
			input:    "a",
			expected: []byte{0x0a},
			wantErr:  false,
		},
		{
			name:     "Single character with 0x prefix",
			input:    "0xa",
			expected: []byte{0x0a},
			wantErr:  false,
		},
		{
			name:     "Upper case hex",
			input:    "ABCDEF",
			expected: []byte{0xAB, 0xCD, 0xEF},
			wantErr:  false,
		},
		{
			name:     "Mixed case hex",
			input:    "aBcDeF",
			expected: []byte{0xAB, 0xCD, 0xEF},
			wantErr:  false,
		},
		{
			name:     "Zero values",
			input:    "0000",
			expected: []byte{0x00, 0x00},
			wantErr:  false,
		},
		{
			name:     "Only 0x prefix",
			input:    "0x",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "Long hex string",
			input:    "0102030405060708090a0b0c0d0e0f",
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			wantErr:  false,
		},
		{
			name:     "Invalid hex character",
			input:    "12ZZ",
			expected: nil,
			wantErr:  true,
		},
		{
			name:     "Invalid hex with 0x prefix",
			input:    "0x12ZZ",
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeHexRelaxed(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeHexRelaxed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.expected) {
				t.Errorf("DecodeHexRelaxed() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDecodeHexRelaxedEdgeCases(t *testing.T) {
	specialCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "With spaces",
			input:   "12 34",
			wantErr: true,
		},
		{
			name:    "With 0x in the middle",
			input:   "120x34",
			wantErr: true,
		},
	}

	for _, tt := range specialCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeHexRelaxed(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeHexRelaxed() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
