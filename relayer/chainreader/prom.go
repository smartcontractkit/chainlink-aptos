package chainreader

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
)

var (
	sqlLatencyBuckets = prometheus.ExponentialBuckets(
		0.01, // Start: 10ms
		2.0,  // Factor: double each time
		10,   // Count: 10 buckets
	)

	promCRQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "cr_query_duration",
		Help:    "Measures duration of ChainReader's queries fetching events",
		Buckets: sqlLatencyBuckets,
	}, []string{"chainFamily", "chainID", "networkName", "query", "event"})

	promCRQueryDataSets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cr_query_dataset_size",
		Help: "Measures size of the datasets returned by ChainReader's queries",
	}, []string{"chainFamily", "chainID", "networkName", "query", "event"})
)

func RecordQueryDuration(chainInfo monitor.ChainInfo, queryType, eventKey string, duration time.Duration) {
	promCRQueryDuration.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		queryType,
		eventKey,
	).Observe(float64(duration.Milliseconds()))
}

func RecordQueryResultSize(chainInfo monitor.ChainInfo, queryType, eventKey string, count int) {
	promCRQueryDataSets.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		queryType,
		eventKey,
	).Set(float64(count))
}
