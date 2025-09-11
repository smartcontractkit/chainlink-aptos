package logpoller

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	promLpEventsInserted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "log_poller_events_inserted",
		Help: "Counter to track number of events inserted by Log Poller",
	}, []string{"chainFamily", "chainID", "event", "is_synthetic"})
)

func ReportEventsInserted(chainID, event string, isSynthetic bool, count int) {
	promLpEventsInserted.WithLabelValues(
		"aptos",
		chainID,
		event,
		strconv.FormatBool(isSynthetic),
	).Add(float64(count))
}
