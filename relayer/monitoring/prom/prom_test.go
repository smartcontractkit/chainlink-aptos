package prom

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
	"github.com/stretchr/testify/require"
)

func TestSetAccountBalance(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(promAccountBalance)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "1",
		NetworkName:     "mainnet",
	}
	account := "0xabc"
	balance := 123.45

	SetAccountBalance(chainInfo, account, balance)

	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	mf := metrics[0]
	require.Equal(t, "aptos_account_balance", mf.GetName())
	require.Len(t, mf.Metric, 1)

	m := mf.Metric[0]
	labels := map[string]string{}
	for _, lp := range m.Label {
		labels[lp.GetName()] = lp.GetValue()
	}
	require.Equal(t, "aptos", labels["chainFamily"])
	require.Equal(t, "1", labels["chainID"])
	require.Equal(t, "mainnet", labels["networkName"])
	require.Equal(t, account, labels["account"])
	require.Equal(t, balance, m.Gauge.GetValue())
}

func TestSetClientLatency(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(promRPCCallLatency)

	chainInfo := types.ChainInfo{
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

func TestReportEventsInserted(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(promLpEventsInserted)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "42",
		NetworkName:     "devnet",
	}
	event := "Transfer"

	ReportEventsInserted(chainInfo, event, false, 3)
	ReportEventsInserted(chainInfo, event, true, 7)

	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	mf := metrics[0]
	require.Equal(t, "aptos_log_poller_events_inserted", mf.GetName())
	require.Len(t, mf.Metric, 2)

	foundSynthetic, foundReal := false, false
	for _, m := range mf.Metric {
		labels := map[string]string{}
		for _, lp := range m.Label {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["isSynthetic"] == "true" {
			foundSynthetic = true
			require.Equal(t, "aptos", labels["chainFamily"])
			require.Equal(t, "42", labels["chainID"])
			require.Equal(t, "devnet", labels["networkName"])
			require.Equal(t, event, labels["event"])
			require.Equal(t, float64(7), m.Counter.GetValue())
		}
		if labels["isSynthetic"] == "false" {
			foundReal = true
			require.Equal(t, float64(3), m.Counter.GetValue())
		}
	}
	require.True(t, foundSynthetic)
	require.True(t, foundReal)
}

func TestRecordQueryDurationAndResultSize(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Create local metrics for testing
	testQueryDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aptos_cr_query_duration",
			Help:    "Measures duration of ChainReader's queries fetching events",
			Buckets: prometheus.ExponentialBuckets(0.01, 2.0, 10),
		},
		[]string{"chainFamily", "chainID", "networkName", "query", "event"},
	)
	testQueryDataSets := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "aptos_cr_query_dataset_size",
			Help: "Measures size of the datasets returned by ChainReader's queries",
		},
		[]string{"chainFamily", "chainID", "networkName", "query", "event"},
	)

	registry.MustRegister(testQueryDuration)
	registry.MustRegister(testQueryDataSets)

	chainInfo := types.ChainInfo{
		ChainFamilyName: "aptos",
		ChainID:         "99",
		NetworkName:     "localnet",
	}
	query := "GetEvents"
	event := "Deposit"

	testQueryDuration.WithLabelValues(chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, query, event).Observe(float64(120))
	testQueryDataSets.WithLabelValues(chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, query, event).Set(float64(42))

	metrics, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, metrics, 2)

	var foundDuration, foundSize bool
	for _, mf := range metrics {
		switch mf.GetName() {
		case "aptos_cr_query_duration":
			require.Len(t, mf.Metric, 1)
			m := mf.Metric[0]
			labels := map[string]string{}
			for _, lp := range m.Label {
				labels[lp.GetName()] = lp.GetValue()
			}
			require.Equal(t, "aptos", labels["chainFamily"])
			require.Equal(t, "99", labels["chainID"])
			require.Equal(t, "localnet", labels["networkName"])
			require.Equal(t, query, labels["query"])
			require.Equal(t, event, labels["event"])
			require.Equal(t, float64(120), m.Histogram.GetSampleSum())
			require.Equal(t, uint64(1), m.Histogram.GetSampleCount())
			foundDuration = true
		case "aptos_cr_query_dataset_size":
			require.Len(t, mf.Metric, 1)
			m := mf.Metric[0]
			labels := map[string]string{}
			for _, lp := range m.Label {
				labels[lp.GetName()] = lp.GetValue()
			}
			require.Equal(t, "aptos", labels["chainFamily"])
			require.Equal(t, "99", labels["chainID"])
			require.Equal(t, "localnet", labels["networkName"])
			require.Equal(t, query, labels["query"])
			require.Equal(t, event, labels["event"])
			require.Equal(t, float64(42), m.Gauge.GetValue())
			foundSize = true
		}
	}
	require.True(t, foundDuration)
	require.True(t, foundSize)
}
