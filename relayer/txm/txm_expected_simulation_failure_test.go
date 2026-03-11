package txm

import (
	"context"
	"errors"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestTxmExpectedMatchSimulationFailure(t *testing.T) {
	testCases := []struct {
		name    string
		err     error
		rules   []ExpectedSimulationFailureRule
		matches bool
	}{
		{
			name: "nil error never matches",
			err:  nil,
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			matches: false,
		},
		{
			name: "matching expected error substring",
			err:  errors.New("Move abort: E_ALREADY_PROCESSED"),
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			matches: true,
		},
		{
			name:    "empty substring matches everything",
			err:     errors.New("some other error"),
			rules:   []ExpectedSimulationFailureRule{{ErrorContains: ""}},
			matches: true,
		},
		{
			name: "non-matching error",
			err:  errors.New("some other error"),
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			matches: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.matches, matchExpectedSimulationFailure(tc.err, tc.rules))
		})
	}
}

func TestTxmExpectedEnqueueCopiesSimulationFailureRules(t *testing.T) {
	txm := &AptosTxm{
		baseLogger:    logger.Test(t),
		transactions:  make(map[string]*AptosTx),
		config:        DefaultConfigSet,
		broadcastChan: make(chan string, 1),
	}

	expectedSimulationFailures := []ExpectedSimulationFailureRule{{ErrorContains: "E_ALREADY_PROCESSED"}}
	err := txm.Enqueue(
		"tx-id",
		nil,
		"0x1",
		"4f3edf983ac63f6f7f4d9b90fba7d3b4d8e0dca54d9b0f1d64c5a1d6a6c2f5e8",
		"0x1::module::function",
		nil,
		nil,
		nil,
		false,
		expectedSimulationFailures...,
	)
	require.NoError(t, err)

	expectedSimulationFailures[0].ErrorContains = "mutated"

	status, getErr := txm.GetStatus("tx-id")
	require.NoError(t, getErr)
	require.Equal(t, commontypes.Pending, status)
	require.Len(t, txm.transactions["tx-id"].ExpectedSimulationFailureRules, 1)
	require.Equal(t, "E_ALREADY_PROCESSED", txm.transactions["tx-id"].ExpectedSimulationFailureRules[0].ErrorContains)
}

func TestTxmExpectedSignAndBroadcastMarksFailedWithoutInflightTx(t *testing.T) {
	client := &stubExpectedSimulationFailureClient{
		chainID:         4,
		ledgerTimestamp: 1_000_000,
		sequenceNumber:  0,
		vmStatus:        "Move abort: E_ALREADY_PROCESSED",
	}
	txm := &AptosTxm{
		baseLogger:    logger.Test(t),
		config:        DefaultConfigSet,
		transactions:  make(map[string]*AptosTx),
		broadcastChan: make(chan string, 1),
		accountStore:  NewAccountStore(),
		getClient: func() (aptos.AptosRpcClient, error) {
			return client, nil
		},
	}

	err := txm.Enqueue(
		"tx-id",
		nil,
		"0x1",
		"4f3edf983ac63f6f7f4d9b90fba7d3b4d8e0dca54d9b0f1d64c5a1d6a6c2f5e8",
		"0x1::module::function",
		nil,
		nil,
		nil,
		true,
		ExpectedSimulationFailureRule{ErrorContains: "E_ALREADY_PROCESSED"},
	)
	require.NoError(t, err)
	<-txm.broadcastChan

	txm.signAndBroadcast(context.Background(), txm.transactions["tx-id"])

	status, getErr := txm.GetStatus("tx-id")
	require.NoError(t, getErr)
	require.Equal(t, commontypes.Failed, status)
	require.Equal(t, 0, txm.accountStore.GetTotalInflightCount())
}

type stubExpectedSimulationFailureClient struct {
	aptos.AptosRpcClient
	chainID         uint8
	ledgerTimestamp uint64
	sequenceNumber  uint64
	vmStatus        string
}

func (c *stubExpectedSimulationFailureClient) GetChainId() (uint8, error) {
	return c.chainID, nil
}

func (c *stubExpectedSimulationFailureClient) Info() (aptos.NodeInfo, error) {
	return aptos.NodeInfo{LedgerTimestampStr: "1000000"}, nil
}

func (c *stubExpectedSimulationFailureClient) Account(address aptos.AccountAddress, ledgerVersion ...uint64) (aptos.AccountInfo, error) {
	return aptos.AccountInfo{SequenceNumberStr: "0"}, nil
}

func (c *stubExpectedSimulationFailureClient) SimulateTransaction(rawTx *aptos.RawTransaction, sender aptos.TransactionSigner, options ...any) ([]*aptosapi.UserTransaction, error) {
	return []*aptosapi.UserTransaction{{Success: false, VmStatus: c.vmStatus}}, nil
}
