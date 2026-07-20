package prom

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/smartcontractkit/chainlink-framework/metrics"

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

	promLpPrunedOffsetTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_log_poller_pruned_offset_total",
		Help: "Total number of times LogPoller detected a pruned event offset on the Aptos node",
	}, []string{"chainFamily", "chainID", "networkName", "event"})

	promLpReaderLagSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "aptos_log_poller_reader_lag_seconds",
		Help:    "Time between event block timestamp and LogPoller insertion time, in seconds",
		Buckets: []float64{1, 2, 5, 10, 30, 60, 120, 300, 600, 1800, 3600},
	}, []string{"chainFamily", "chainID", "networkName", "event"})

	promLpEventSequenceGap = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_log_poller_event_sequence_gap",
		Help: "Total number of event sequence number gaps detected by LogPoller",
	}, []string{"chainFamily", "chainID", "networkName", "event"})

	promLpPrunedWarningActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aptos_log_poller_pruned_warning_active",
		Help: "Set to 1 while a LogPoller event handle is in a pruned/gap warning state (CR stays operational; NOP should act), 0 when recovered. This is the paging signal — wire Prometheus alert rules to fire when this gauge is 1 for > N minutes.",
	}, []string{"chainFamily", "chainID", "networkName", "event"})

	promLpFatalErrorTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_log_poller_fatal_error_total",
		Help: "Total number of fatal (non-transient, non-pruned) RPC errors from EventsByCreationNumber, e.g. 404 misconfiguration. The CR does not halt but these are logged at Error for NOP attention.",
	}, []string{"chainFamily", "chainID", "networkName", "event"})
)

func SetAccountBalance(chainInfo types.ChainInfo, account string, balance float64) {
	promAccountBalance.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		account,
	).Set(balance)

	metrics.NodeBalance.WithLabelValues(
		account,
		chainInfo.ChainID,
		chainInfo.ChainFamilyName,
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

// ReportPrunedOffset increments the pruned offset counter for the given event.
func ReportPrunedOffset(chainInfo types.ChainInfo, event string) {
	promLpPrunedOffsetTotal.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
	).Inc()
}

// ObserveReaderLag records the lag between an event's block timestamp and now.
func ObserveReaderLag(chainInfo types.ChainInfo, event string, lagSeconds float64) {
	promLpReaderLagSeconds.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
	).Observe(lagSeconds)
}

// ReportEventSequenceGap increments the sequence gap counter by the given gap size.
func ReportEventSequenceGap(chainInfo types.ChainInfo, event string, gapSize uint64) {
	promLpEventSequenceGap.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
	).Add(float64(gapSize))
}

// SetPrunedWarning sets the pruned-warning-active gauge for the given event handle.
// active=true raises the warning (gauge=1, the paging signal for the NOP); active=false
// clears it (gauge=0, auto-recovery). The CR does NOT halt regardless of the gauge value.
func SetPrunedWarning(chainInfo types.ChainInfo, event string, active bool) {
	val := 0.0
	if active {
		val = 1.0
	}
	promLpPrunedWarningActive.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
	).Set(val)
}

// ReportFatalError increments the fatal-error counter for the given event.
func ReportFatalError(chainInfo types.ChainInfo, event string) {
	promLpFatalErrorTotal.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
	).Inc()
}

// --- Test helpers (used by logpoller tests to assert metric behavior) ---
// These read the process-wide promauto-registered metrics. Tests must use unique
// chainID/networkName/event label values to avoid interference between parallel tests.

// PrunedWarningActiveValue returns the current value of aptos_log_poller_pruned_warning_active
// for the given labels. For use in tests only.
func PrunedWarningActiveValue(chainInfo types.ChainInfo, event string) float64 {
	return testutil.ToFloat64(promLpPrunedWarningActive.WithLabelValues(
		chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, event))
}

// PrunedOffsetTotalValue returns the current value of aptos_log_poller_pruned_offset_total
// for the given labels. For use in tests only.
func PrunedOffsetTotalValue(chainInfo types.ChainInfo, event string) float64 {
	return testutil.ToFloat64(promLpPrunedOffsetTotal.WithLabelValues(
		chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, event))
}

// EventSequenceGapValue returns the current value of aptos_log_poller_event_sequence_gap
// for the given labels. For use in tests only.
func EventSequenceGapValue(chainInfo types.ChainInfo, event string) float64 {
	return testutil.ToFloat64(promLpEventSequenceGap.WithLabelValues(
		chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, event))
}

// FatalErrorTotalValue returns the current value of aptos_log_poller_fatal_error_total
// for the given labels. For use in tests only.
func FatalErrorTotalValue(chainInfo types.ChainInfo, event string) float64 {
	return testutil.ToFloat64(promLpFatalErrorTotal.WithLabelValues(
		chainInfo.ChainFamilyName, chainInfo.ChainID, chainInfo.NetworkName, event))
}
