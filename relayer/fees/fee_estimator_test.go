package fees

import (
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/stretchr/testify/assert"

	rlclient "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/client/mock"
)

func TestEstimateGasPrice(t *testing.T) {
	mockClient := new(rlclient.RateLimitedClient)
	mockClient.On("EstimateGasPrice").Return(aptos.EstimateGasInfo{
		GasEstimate:              100,
		DeprioritizedGasEstimate: 50,
		PrioritizedGasEstimate:   150,
	}, nil)

	tests := []struct {
		strategy FeeStrategy
		expected uint64
	}{
		{Deprioritized, 50},
		{Default, 100},
		{Prioritized, 150},
	}

	for _, tt := range tests {
		estimator := NewFeeEstimator(mockClient)
		gasInfo, err := estimator.EstimateGasPrice()
		assert.NoError(t, err)

		var gasPrice uint64
		switch tt.strategy {
		case Deprioritized:
			gasPrice = gasInfo.DeprioritizedGasEstimate
		case Prioritized:
			gasPrice = gasInfo.PrioritizedGasEstimate
		default:
			gasPrice = gasInfo.GasEstimate
		}

		assert.Equal(t, tt.expected, gasPrice)
	}

	mockClient.AssertExpectations(t)
}
