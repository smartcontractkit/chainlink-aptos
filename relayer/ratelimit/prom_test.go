package ratelimit

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/stretchr/testify/require"
)

func TestSetClientLatency(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(rpcCallLatency)

	chainInfo := monitor.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "123",
		NetworkName:     "testnet",
	}
	url := "https://aptos-testnet.example.com"
	request := "getLatestBlock"

	// Record success
	SetClientLatency(chainInfo, 150*time.Millisecond, request, url, nil)
	// Record failure
	SetClientLatency(chainInfo, 2500*time.Millisecond, request, url, errors.New("fail"))

	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	mf := metrics[0]
	require.Equal(t, "aptos_rpc_call_latency", mf.GetName())
	require.Len(t, mf.Metric, 2)

	foundSuccess, foundFailure := false, false
	for _, m := range mf.Metric {
		labels := map[string]string{}
		for _, lp := range m.Label {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["success"] == "true" {
			foundSuccess = true
			require.Equal(t, "aptos", labels["chainFamily"])
			require.Equal(t, "123", labels["chainID"])
			require.Equal(t, "testnet", labels["networkName"])
			require.Equal(t, url, labels["rpcUrl"])
			require.Equal(t, request, labels["rpcCallName"])
			require.Equal(t, float64(150), m.Histogram.GetSampleSum())
			require.Equal(t, uint64(1), m.Histogram.GetSampleCount())
		}
		if labels["success"] == "false" {
			foundFailure = true
			require.Equal(t, float64(2500), m.Histogram.GetSampleSum())
			require.Equal(t, uint64(1), m.Histogram.GetSampleCount())
		}
	}
	require.True(t, foundSuccess, "success metric not found")
	require.True(t, foundFailure, "failure metric not found")
}
