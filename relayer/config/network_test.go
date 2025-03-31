package config

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
)

func TestGetNetworkConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		chainID string
		want    aptos.NetworkConfig
		wantErr bool
	}{
		{"1", aptos.MainnetConfig, false},
		{"2", aptos.TestnetConfig, false},
		{"4", aptos.LocalnetConfig, false},
		{"999", aptos.NetworkConfig{}, true}, // Unknown chainID
		{"abc", aptos.NetworkConfig{}, true}, // Invalid chainID
		{"", aptos.NetworkConfig{}, true},    // Empty chainID
	}

	for _, tt := range tests {
		t.Run(tt.chainID, func(t *testing.T) {
			t.Parallel()
			got, err := GetNetworkConfig(tt.chainID)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
