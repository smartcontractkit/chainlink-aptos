package ratelimit

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
)

// Redefining metric from https://github.com/smartcontractkit/chainlink-framework/blob/main/metrics/client.go
// because it does not have all the required labels
var (
	rpcCallLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
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
)

func SetClientLatency(chainInfo monitor.ChainInfo, d time.Duration, request, url string, err error) {
	rpcCallLatency.WithLabelValues(
		chainInfo.ChainFamilyName,
		chainInfo.ChainID,
		chainInfo.NetworkName,
		url,
		strconv.FormatBool(err == nil), // is successful
		request,                        // rpc call name
	).Observe(float64(d.Milliseconds()))
}
