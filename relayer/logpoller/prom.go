package logpoller

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
)

var (
	promLpEventsInserted = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "log_poller_events_inserted",
		Help: "Counter to track number of events inserted by LogPoller",
	}, []string{"chainFamily", "chainID", "networkName", "event", "isSynthetic"})
)

func ReportEventsInserted(chainInfo monitor.ChainInfo, event string, isSynthetic bool, count int) {
	promLpEventsInserted.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		event,
		strconv.FormatBool(isSynthetic),
	).Add(float64(count))
}
