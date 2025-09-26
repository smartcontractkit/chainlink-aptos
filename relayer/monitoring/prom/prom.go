package prom

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/smartcontractkit/chainlink-aptos/relayer/types"
)

var (
	sqlLatencyBuckets = prometheus.ExponentialBuckets(
		0.01, // Start: 10ms
		2.0,  // Factor: double each time
		10,   // Count: 10 buckets
	)

	promAccountBalance = promauto.NewGaugeVec(
		prometheus.GaugeOpts{Name: "aptos_account_balance", Help: "Account balances"},
		[]string{"chainFamily", "chainID", "networkName", "account"},
	)

	// Redefining metric from https://github.com/smartcontractkit/chainlink-framework/blob/main/metrics/client.go
	// because it does not have all the required labels
	promRPCCallLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "aptos_rpc_call_latency",
		Help: "The duration of an RPC call in milliseconds",
		Buckets: []float64{
			float64(50 * time.Millisecond),
			float64(100 * time.Millisecond),
			float64(200 * time.Millisecond),
			float64(500 * time.Millisecond),
			float64(1 * time.Second),
			float64(2 * time.Second),
			float64(4 * time.Second),
			float64(8 * time.Second),
		},
	}, []string{"chainFamily", "chainID", "networkName", "rpcUrl", "success", "rpcCallName"})

	promLpEventsInserted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_log_poller_events_inserted",
		Help: "Counter to track number of events inserted by LogPoller",
	}, []string{"chainFamily", "chainID", "networkName", "event", "isSynthetic"})

	promCRQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aptos_cr_query_duration",
		Help:    "Measures duration of ChainReader's queries fetching events",
		Buckets: sqlLatencyBuckets,
	}, []string{"chainFamily", "chainID", "networkName", "query", "event"})

	promCRQueryDataSets = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aptos_cr_query_dataset_size",
		Help: "Measures size of the datasets returned by ChainReader's queries",
	}, []string{"chainFamily", "chainID", "networkName", "query", "event"})
)

func SetAccountBalance(chainInfo types.ChainInfo, account string, balance float64) {
	promAccountBalance.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		account,
	).Set(balance)
}

func SetClientLatency(chainInfo types.ChainInfo, d time.Duration, request, url string, err error) {
	promRPCCallLatency.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		url,
		strconv.FormatBool(err == nil), // is successful
		request,                        // rpc call name
	).Observe(float64(d.Milliseconds()))
}

func ReportEventsInserted(chainInfo types.ChainInfo, event string, isSynthetic bool, count int) {
	promLpEventsInserted.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
		strconv.FormatBool(isSynthetic),
	).Add(float64(count))
}

func RecordQueryDuration(chainInfo types.ChainInfo, queryType, eventKey string, duration time.Duration) {
	promCRQueryDuration.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		queryType,
		eventKey,
	).Observe(float64(duration.Milliseconds()))
}

func RecordQueryResultSize(chainInfo types.ChainInfo, queryType, eventKey string, count int) {
	promCRQueryDataSets.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		queryType,
		eventKey,
	).Set(float64(count))
}
