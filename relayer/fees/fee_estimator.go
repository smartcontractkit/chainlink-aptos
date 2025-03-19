package fees

import (
	"github.com/aptos-labs/aptos-go-sdk"

	rlclient "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/client"
)

type FeeStrategy int

const (
	Deprioritized FeeStrategy = -1
	Default       FeeStrategy = 0
	Prioritized   FeeStrategy = 1
)

type FeeEstimator struct {
	client rlclient.RateLimitedClient
}

func NewFeeEstimator(cl rlclient.RateLimitedClient) *FeeEstimator {
	return &FeeEstimator{
		client: cl,
	}
}

func (f *FeeEstimator) EstimateGasPrice() (aptos.EstimateGasInfo, error) {
	return f.client.EstimateGasPrice()
}
