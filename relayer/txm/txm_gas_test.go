package txm

import (
	"math/big"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/require"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"

	clientmocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
)

// TestCreateRawTxMaxGasAmount ensures that the max gas amount is resolved in the
// following order:
//  1. the gas limit from the tx metadata, if set
//  2. the gas limit overhead is added on top, if configured
//  3. the default max gas amount, but only if the result is still zero
//
// This ensures the default max gas amount never applies to CCIP messages, which
// always carry an explicit gas limit (possibly 0).
func TestCreateRawTxMaxGasAmount(t *testing.T) {
	const ledgerTimestamp = "1700000000000000" // microseconds

	tests := []struct {
		name           string
		metadata       *commontypes.TxMeta
		defaultMaxGas  uint64
		overhead       uint64
		expectedMaxGas uint64
	}{
		{
			name:           "gas limit from metadata with overhead",
			metadata:       &commontypes.TxMeta{GasLimit: big.NewInt(100_000)},
			defaultMaxGas:  2_000_000,
			overhead:       50_000,
			expectedMaxGas: 150_000,
		},
		{
			name:           "zero gas limit from metadata with overhead does not use default",
			metadata:       &commontypes.TxMeta{GasLimit: big.NewInt(0)},
			defaultMaxGas:  2_000_000,
			overhead:       50_000,
			expectedMaxGas: 50_000,
		},
		{
			name:           "nil gas limit with overhead does not use default",
			metadata:       &commontypes.TxMeta{},
			defaultMaxGas:  2_000_000,
			overhead:       50_000,
			expectedMaxGas: 50_000,
		},
		{
			name:           "nil metadata with overhead does not use default",
			metadata:       nil,
			defaultMaxGas:  2_000_000,
			overhead:       50_000,
			expectedMaxGas: 50_000,
		},
		{
			name:           "zero gas limit without overhead falls back to default",
			metadata:       &commontypes.TxMeta{GasLimit: big.NewInt(0)},
			defaultMaxGas:  2_000_000,
			overhead:       0,
			expectedMaxGas: 2_000_000,
		},
		{
			name:           "nil gas limit without overhead falls back to default",
			metadata:       &commontypes.TxMeta{},
			defaultMaxGas:  2_000_000,
			overhead:       0,
			expectedMaxGas: 2_000_000,
		},
		{
			name:           "gas limit from metadata without overhead is unchanged",
			metadata:       &commontypes.TxMeta{GasLimit: big.NewInt(100_000)},
			defaultMaxGas:  2_000_000,
			overhead:       0,
			expectedMaxGas: 100_000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := clientmocks.NewAptosRpcClient(t)
			client.On("GetChainId").Return(uint8(4), nil).Maybe()
			client.On("Info").Return(aptos.NodeInfo{LedgerTimestampStr: ledgerTimestamp}, nil).Maybe()
			client.On("EstimateGasPrice").Return(aptos.EstimateGasInfo{GasEstimate: 100}, nil).Maybe()

			// copy the default config set and override the fields under test to
			// avoid mutating the shared package-level pointers
			config := DefaultConfigSet
			config.DefaultMaxGasAmount = &tt.defaultMaxGas
			config.GasLimitOverhead = &tt.overhead

			txm := &AptosTxm{
				baseLogger: logger.Test(t),
				config:     config,
			}

			tx := &AptosTx{
				ID:       "test-tx",
				Metadata: tt.metadata,
				Simulate: false,
			}

			rawTx, err := txm.createRawTx(client, tx, 0)
			require.NoError(t, err)
			require.Equal(t, tt.expectedMaxGas, rawTx.MaxGasAmount)
		})
	}
}
