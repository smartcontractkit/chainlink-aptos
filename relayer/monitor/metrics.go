package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TODO: replace with Beholder metrics
var promWTAccountBalance = promauto.NewGaugeVec(
	prometheus.GaugeOpts{Name: "write-target_account-balance", Help: "Balance for configured WT account"},
	[]string{"account", "network_chain_id", "network_name", "denomination"},
)
