package chainwriter

import (
	"testing"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
)

func TestEncodeFunctionParams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		argMap     map[string]interface{}
		params     []config.AptosFunctionParam
		wantTypes  []string
		wantValues []any
		wantErr    string
	}{
		{
			name: "All arguments provided",
			argMap: map[string]interface{}{
				"arg1": "value1",
				"arg2": 42,
			},
			params: []config.AptosFunctionParam{
				{Name: "arg1", Type: "string", Required: true},
				{Name: "arg2", Type: "int", Required: true},
			},
			wantTypes:  []string{"string", "int"},
			wantValues: []any{"value1", 42},
		},
		{
			name: "Missing required argument",
			argMap: map[string]interface{}{
				"arg1": "value1",
			},
			params: []config.AptosFunctionParam{
				{Name: "arg1", Type: "string", Required: true},
				{Name: "arg2", Type: "int", Required: true},
			},
			wantErr: "missing argument: arg2",
		},
		{
			name: "Using default values",
			argMap: map[string]interface{}{
				"arg1": "value1",
			},
			params: []config.AptosFunctionParam{
				{Name: "arg1", Type: "string", Required: true},
				{Name: "arg2", Type: "int", Required: false, DefaultValue: 42},
			},
			wantTypes:  []string{"string", "int"},
			wantValues: []any{"value1", 42},
		},
		{
			name: "Optional param provided",
			argMap: map[string]interface{}{
				"arg1": "value1",
				"arg2": 100,
			},
			params: []config.AptosFunctionParam{
				{Name: "arg1", Type: "string", Required: true},
				{Name: "arg2", Type: "int", Required: false, DefaultValue: 42},
			},
			wantTypes:  []string{"string", "int"},
			wantValues: []any{"value1", 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			types, values, err := convertFunctionParams(tt.argMap, tt.params)

			if err != nil {
				if err.Error() != tt.wantErr {
					t.Errorf("Expected error '%v', got '%v'", tt.wantErr, err)
				}
				return
			}

			if tt.wantErr != "" {
				t.Errorf("Expected error '%v', got nil", tt.wantErr)
				return
			}

			if len(types) != len(tt.wantTypes) {
				t.Errorf("Expected types length %d, got %d", len(tt.wantTypes), len(types))
			} else {
				for i := range types {
					if types[i] != tt.wantTypes[i] {
						t.Errorf("Expected type %s, got %s", tt.wantTypes[i], types[i])
					}
				}
			}

			if len(values) != len(tt.wantValues) {
				t.Errorf("Expected values length %d, got %d", len(tt.wantValues), len(values))
			} else {
				for i := range values {
					if values[i] != tt.wantValues[i] {
						t.Errorf("Expected value %v, got %v", tt.wantValues[i], values[i])
					}
				}
			}
		})
	}
}
