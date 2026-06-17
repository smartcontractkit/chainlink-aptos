package ccip

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	chain_selectors "github.com/smartcontractkit/chain-selectors"
	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/stretchr/testify/require"

	jdtest "github.com/smartcontractkit/chainlink/deployment/environment/test"
)

func TestPatchJDTestOCRNodeKeys(t *testing.T) {
	t.Parallel()

	aptosSelector := chain_selectors.APTOS_LOCALNET.Selector
	evmSelector := chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector

	nodes := jdtest.NewNodes(t, []jdtest.NodeConfig{{
		Name:           "node-1",
		ChainSelectors: []uint64{evmSelector, aptosSelector},
	}})
	patchJDTestOCRNodeKeys(t, nodes)

	aptosCfg, ok := nodes[0].OCRConfigForChainSelector(aptosSelector)
	require.True(t, ok)
	require.Len(t, aptosCfg.OnchainPublicKey, ed25519.PublicKeySize)

	transmitterBytes, err := hex.DecodeString(string(aptosCfg.TransmitAccount))
	require.NoError(t, err)
	require.Equal(t, []byte(aptosCfg.OnchainPublicKey), []byte(transmitterBytes))

	evmCfg, ok := nodes[0].OCRConfigForChainSelector(evmSelector)
	require.True(t, ok)
	require.Contains(t, string(evmCfg.TransmitAccount), "0x", "EVM transmit accounts should remain EVM-style")
}

func TestPatchJDTestOCRNodeKeysChainConfigs(t *testing.T) {
	t.Parallel()

	aptosSelector := chain_selectors.APTOS_LOCALNET.Selector
	evmSelector := chain_selectors.ETHEREUM_TESTNET_SEPOLIA.Selector

	nodes := jdtest.NewNodes(t, []jdtest.NodeConfig{{
		Name:           "node-1",
		ChainSelectors: []uint64{evmSelector, aptosSelector},
	}})
	patchJDTestOCRNodeKeys(t, nodes)

	deploymentNode := *nodes[0]

	chainConfigs, err := deploymentNode.ChainConfigs()
	require.NoError(t, err)

	var aptosAccountAddress string
	for _, cfg := range chainConfigs {
		if cfg.Chain.Type == nodev1.ChainType_CHAIN_TYPE_APTOS {
			aptosAccountAddress = cfg.AccountAddress
			break
		}
	}
	require.NotEmpty(t, aptosAccountAddress)

	transmitterBytes, err := hex.DecodeString(aptosAccountAddress)
	require.NoError(t, err)
	require.Len(t, transmitterBytes, ed25519.PublicKeySize)
}
