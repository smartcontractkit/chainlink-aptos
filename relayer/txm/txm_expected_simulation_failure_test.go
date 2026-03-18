package txm

import (
	"context"
	"errors"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"

	monitormocks "github.com/smartcontractkit/chainlink-aptos/relayer/monitor/mocks"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestTxmExpectedMatchSimulationFailure(t *testing.T) {
	testCases := []struct {
		name   string
		err    error
		rules  []ExpectedSimulationFailureRule
		result expectedSimulationFailureHandling
	}{
		{
			name: "nil error never matches",
			err:  nil,
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			result: expectedSimulationFailureNoMatch,
		},
		{
			name: "matching expected error substring",
			err:  errors.New("Move abort: E_ALREADY_PROCESSED"),
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			result: expectedSimulationFailureAbortBeforeSubmit,
		},
		{
			name:   "empty substring matches everything",
			err:    errors.New("some other error"),
			rules:  []ExpectedSimulationFailureRule{{ErrorContains: ""}},
			result: expectedSimulationFailureAbortBeforeSubmit,
		},
		{
			name: "non-matching error",
			err:  errors.New("some other error"),
			rules: []ExpectedSimulationFailureRule{
				{ErrorContains: "E_ALREADY_PROCESSED"},
				{ErrorContains: "SEQUENCE_NUMBER_TOO_OLD"},
			},
			result: expectedSimulationFailureNoMatch,
		},
		{
			name: "aptos write terminal rule submits receiver aborts once",
			err:  errors.New("Move abort in 0xbeef::receiver: E_USER_ABORT"),
			rules: []ExpectedSimulationFailureRule{
				{Kind: ExpectedSimulationFailureRuleKindAptosWriteTerminal},
			},
			result: expectedSimulationFailureSubmitOnce,
		},
		{
			name: "aptos write terminal rule does not match retryable forwarder aborts",
			err:  errors.New("Move abort in 0xaa::platform::forwarder: E_OUT_OF_GAS"),
			rules: []ExpectedSimulationFailureRule{
				{Kind: ExpectedSimulationFailureRuleKindAptosWriteTerminal},
			},
			result: expectedSimulationFailureNoMatch,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.result, classifyExpectedSimulationFailure(tc.err, tc.rules))
		})
	}
}

func TestTxmExpectedEnqueueWithEntryFunctionCopiesSimulationFailureRules(t *testing.T) {
	txm := &AptosTxm{
		baseLogger:    logger.Test(t),
		transactions:  make(map[string]*AptosTx),
		config:        DefaultConfigSet,
		broadcastChan: make(chan string, 1),
	}

	expectedSimulationFailures := []ExpectedSimulationFailureRule{{
		Kind:          ExpectedSimulationFailureRuleKindAptosWriteTerminal,
		ErrorContains: "unused",
	}}
	_, err := txm.EnqueueWithEntryFunction(
		"tx-id",
		nil,
		"4f3edf983ac63f6f7f4d9b90fba7d3b4d8e0dca54d9b0f1d64c5a1d6a6c2f5e8",
		&aptos.EntryFunction{},
		false,
		expectedSimulationFailures...,
	)
	require.NoError(t, err)

	expectedSimulationFailures[0].Kind = ExpectedSimulationFailureRuleKindSubstring
	expectedSimulationFailures[0].ErrorContains = "mutated"

	require.Len(t, txm.transactions["tx-id"].ExpectedSimulationFailureRules, 1)
	require.Equal(t, ExpectedSimulationFailureRuleKindAptosWriteTerminal, txm.transactions["tx-id"].ExpectedSimulationFailureRules[0].Kind)
	require.Equal(t, "unused", txm.transactions["tx-id"].ExpectedSimulationFailureRules[0].ErrorContains)
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

func TestTxmExpectedAptosWriteTerminalSimulationFailureStillBroadcasts(t *testing.T) {
	client := &stubExpectedSimulationFailureClient{
		chainID:         4,
		ledgerTimestamp: 1_000_000,
		sequenceNumber:  0,
		vmStatus:        "Move abort in 0xbeef::receiver: E_USER_ABORT",
		submitHash:      "0xabc123",
	}
	keystore := monitormocks.NewKeystore(t)
	keystore.EXPECT().Sign(mock.Anything, mock.Anything, mock.Anything).Return(make([]byte, 64), nil)
	metrics, err := newAptosTxmMetrics("4")
	require.NoError(t, err)
	txm := &AptosTxm{
		baseLogger:    logger.Test(t),
		keystore:      keystore,
		config:        DefaultConfigSet,
		metrics:       metrics,
		transactions:  make(map[string]*AptosTx),
		broadcastChan: make(chan string, 1),
		accountStore:  NewAccountStore(),
		getClient: func() (aptos.AptosRpcClient, error) {
			return client, nil
		},
	}

	err = txm.Enqueue(
		"tx-id",
		nil,
		"0x1",
		"4f3edf983ac63f6f7f4d9b90fba7d3b4d8e0dca54d9b0f1d64c5a1d6a6c2f5e8",
		"0x1::module::function",
		nil,
		nil,
		nil,
		true,
		ExpectedSimulationFailureRule{Kind: ExpectedSimulationFailureRuleKindAptosWriteTerminal},
	)
	require.NoError(t, err)
	<-txm.broadcastChan

	txm.signAndBroadcast(context.Background(), txm.transactions["tx-id"])

	status, getErr := txm.GetStatus("tx-id")
	require.NoError(t, getErr)
	require.Equal(t, commontypes.Unconfirmed, status)
	require.Equal(t, 1, txm.accountStore.GetTotalInflightCount())

	txResult, resultErr := txm.GetTransactionResult("tx-id")
	require.NoError(t, resultErr)
	require.Equal(t, "0xabc123", txResult.TxHash)
	require.Contains(t, txResult.VmStatus, "E_USER_ABORT")
}

type stubExpectedSimulationFailureClient struct {
	aptos.AptosRpcClient
	chainID         uint8
	ledgerTimestamp uint64
	sequenceNumber  uint64
	vmStatus        string
	submitHash      string
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

func (c *stubExpectedSimulationFailureClient) EstimateGasPrice() (aptos.EstimateGasInfo, error) {
	return aptos.EstimateGasInfo{
		GasEstimate:            100,
		PrioritizedGasEstimate: 110,
	}, nil
}

func (c *stubExpectedSimulationFailureClient) SubmitTransaction(signedTx *aptos.SignedTransaction) (*aptosapi.SubmitTransactionResponse, error) {
	if c.submitHash == "" {
		return nil, errors.New("unexpected submit")
	}
	return &aptosapi.SubmitTransactionResponse{Hash: c.submitHash}, nil
}
