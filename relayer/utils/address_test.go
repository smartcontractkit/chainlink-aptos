package utils

import (
	"testing"
)

func TestHexAddressToAddressCanonicalRepresentation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input          string
		expectedOutput string
		expectError    bool
	}{
		{
			input:          "0x1", // Aptos special addresses (canonical representation is short)
			expectedOutput: "0x1",
			expectError:    false,
		},
		{
			input:          "0x123456723232323232323232323232323890abcdef",
			expectedOutput: "0x0000000000000000000000123456723232323232323232323232323890abcdef",
			expectError:    false,
		},
		{
			input:          "0x080e899c2f3f5fb4f207953d9ecdedf86faa940756c6e4f47c55c45d8c1ae7b9",
			expectedOutput: "0x080e899c2f3f5fb4f207953d9ecdedf86faa940756c6e4f47c55c45d8c1ae7b9",
			expectError:    false,
		},
		{
			input:          "0x80e899c2f3f5fb4f207953d9ecdedf86faa940756c6e4f47c55c45d8c1ae7b9",
			expectedOutput: "0x080e899c2f3f5fb4f207953d9ecdedf86faa940756c6e4f47c55c45d8c1ae7b9",
			expectError:    false,
		},
		{
			input:       "invalid_address",
			expectError: true,
		},
	}

	for _, test := range tests {
		output, err := HexAddressToAddress(test.input)
		if test.expectError {
			if err == nil {
				t.Errorf("expected error for input %s, but got none", test.input)
			}
		} else {
			if err != nil {
				t.Errorf("did not expect error for input %s, but got %v", test.input, err)
			}
			if output.String() != test.expectedOutput {
				t.Errorf("expected %s, got %s", test.expectedOutput, output.String())
			}
		}
	}
}
