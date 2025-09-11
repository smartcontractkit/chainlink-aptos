package chainreader

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
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
	}, []string{"chainFamily", "chainID", "query", "event"})
	promCRQueryDataSets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cr_query_dataset_size",
		Help: "Measures size of the datasets returned by ChainReader's queries",
	}, []string{"chainFamily", "chainID", "query", "event"})
)

func RecordQueryDuration(chainID, queryType, eventKey string, duration time.Duration) {
	promCRQueryDuration.WithLabelValues("aptos", chainID, queryType, eventKey).Observe(float64(duration.Milliseconds()))
}

func RecordQueryResultSize(chainID, queryType, eventKey string, count int) {
	promCRQueryDataSets.WithLabelValues("aptos", chainID, queryType, eventKey).Set(float64(count))
}
