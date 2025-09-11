package ratelimit

import (
	"strconv"
	"time"

	"github.com/smartcontractkit/chainlink-framework/metrics"
)

func SetClientLatency(chainID string, d time.Duration, request, url string, err error) {
	metrics.RPCCallLatency.WithLabelValues(
		"aptos",
		chainID,
		url,
		"false",                        // is send only
		strconv.FormatBool(err == nil), // is successful
		request,                        // rpc call name
	).Observe(float64(d))
}
