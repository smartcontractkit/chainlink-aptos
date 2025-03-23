package fees

import (
	"github.com/aptos-labs/aptos-go-sdk"
)

type FeeStrategy int

const (
	Deprioritized FeeStrategy = -1
	Default       FeeStrategy = 0
	Prioritized   FeeStrategy = 1
)

type FeeEstimator struct {
	client aptos.AptosRpcClient
}

func NewFeeEstimator(cl aptos.AptosRpcClient) *FeeEstimator {
	return &FeeEstimator{
		client: cl,
	}
}

func (f *FeeEstimator) EstimateGasPrice() (aptos.EstimateGasInfo, error) {
	return f.client.EstimateGasPrice()
}
