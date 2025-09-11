package chainreader

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/stretchr/testify/require"
)

func TestRecordQueryDurationAndResultSize(t *testing.T) {
	registry := prometheus.NewRegistry()

	// Create local metrics for testing
	testQueryDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "cr_query_duration",
			Help:    "Measures duration of ChainReader's queries fetching events",
			Buckets: prometheus.ExponentialBuckets(0.01, 2.0, 10),
		},
		[]string{"chainFamily", "chainID", "networkName", "query", "event"},
	)
	testQueryDataSets := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cr_query_dataset_size",
			Help: "Measures size of the datasets returned by ChainReader's queries",
		},
		[]string{"chainFamily", "chainID", "networkName", "query", "event"},
	)

	registry.MustRegister(testQueryDuration)
	registry.MustRegister(testQueryDataSets)

	chainInfo := monitor.ChainInfo{
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
		case "cr_query_duration":
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
		case "cr_query_dataset_size":
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
