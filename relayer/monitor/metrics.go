package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// TODO: replace with Beholder metrics
var promWTAccountBalance = promauto.NewGaugeVec(
	// TODO: group this under 'chain' (parent service) not under 'write_target' (original plan)
	prometheus.GaugeOpts{Name: "write_target_account_balance", Help: "Balance for configured WT account"},
	[]string{"account", "network_chain_id", "network_name", "denomination"},
)
