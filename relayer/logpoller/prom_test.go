package logpoller

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/stretchr/testify/require"
)

func TestReportEventsInserted(t *testing.T) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(promLpEventsInserted)

	chainInfo := monitor.ChainInfo{
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
	require.Equal(t, "log_poller_events_inserted", mf.GetName())
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
