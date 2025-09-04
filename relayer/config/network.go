package config

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/aptos-labs/aptos-go-sdk"
)

// GetNetworkConfig returns a known network configuration for the given chain ID.
// A NetworkConfig contains the configuration details for connecting to a specific Aptos network,
// including the network's ChainId, URL, and other relevant settings.
// This function takes a chain ID as a string, validates it, and returns the corresponding NetworkConfig.
func GetNetworkConfig(chainID string) (aptos.NetworkConfig, error) {
	if chainID == "" {
		return aptos.NetworkConfig{}, errors.New("chainID is required")
	}

	// Check if chain ID is a uint8
	id, err := strconv.ParseUint(chainID, 10, 8)
	if err != nil {
		return aptos.NetworkConfig{}, fmt.Errorf("chainID '%s' must be a valid uint8 (0-255): %w", chainID, err)
	}

	// Find network with matching chain ID
	for _, network := range aptos.NamedNetworks {
		if network.ChainId == uint8(id) {
			return network, nil
		}
	}

	return aptos.NetworkConfig{}, fmt.Errorf("network configuration not found for chainID '%s'", chainID)
}
