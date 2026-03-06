package txm

import (
	"errors"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMatchExpectedSimulationFailure(t *testing.T) {
	expectedSimulationFailures := []ExpectedSimulationFailureRule{
		{ErrorContains: "E_ALREADY_PROCESSED"},
		{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
	}

	require.False(t, matchExpectedSimulationFailure(nil, expectedSimulationFailures))
	require.True(t, matchExpectedSimulationFailure(errors.New("Move abort: E_ALREADY_PROCESSED"), expectedSimulationFailures))
	require.True(t, matchExpectedSimulationFailure(errors.New("some other error"), []ExpectedSimulationFailureRule{{ErrorContains: ""}}))
	require.False(t, matchExpectedSimulationFailure(errors.New("some other error"), expectedSimulationFailures))
}

func TestExpectedSimulationFailureErrorCarriesReason(t *testing.T) {
	err := &expectedSimulationFailureError{reason: "Move abort: E_ALREADY_PROCESSED"}

	require.Equal(t, "Move abort: E_ALREADY_PROCESSED", err.Error())

	var expectedErr *expectedSimulationFailureError
	require.True(t, errors.As(err, &expectedErr))
	require.Equal(t, "Move abort: E_ALREADY_PROCESSED", expectedErr.reason)
}

func TestEnqueueCopiesExpectedSimulationFailureRules(t *testing.T) {
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

func TestGetFailureReason(t *testing.T) {
	txm := &AptosTxm{
		transactions: map[string]*AptosTx{
			"failed": {
				Status:        commontypes.Failed,
				FailureReason: "Move abort: E_ALREADY_PROCESSED",
			},
			"pending": {
				Status: commontypes.Pending,
			},
		},
	}

	reason, err := txm.GetFailureReason("failed")
	require.NoError(t, err)
	require.Equal(t, "Move abort: E_ALREADY_PROCESSED", reason)

	_, err = txm.GetFailureReason("pending")
	require.Error(t, err)
	require.ErrorContains(t, err, "transaction not failed")

	_, err = txm.GetFailureReason("missing")
	require.Error(t, err)
	require.ErrorContains(t, err, "no such tx")
}

func TestUpdateTransactionStatusClearsFailureReason(t *testing.T) {
	txm := &AptosTxm{}
	tx := &AptosTx{Status: commontypes.Failed, FailureReason: "failure"}

	txm.updateTransactionStatus(tx, commontypes.Unconfirmed)
	require.Empty(t, tx.FailureReason)
}
