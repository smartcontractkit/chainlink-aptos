package txm

import (
	"context"
	"testing"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/stretchr/testify/require"
)

func TestTxmMaybeRetryReturnsFalseWhenBroadcastChannelIsFull(t *testing.T) {
	txm := &AptosTxm{
		baseLogger:    logger.Test(t),
		broadcastChan: make(chan string, 1),
		config:        DefaultConfigSet,
	}
	txm.broadcastChan <- "existing"

	unconfirmedTx := &UnconfirmedTx{
		Hash: "0xabc",
		Tx: &AptosTx{
			ID: "tx-id",
		},
	}

	require.False(t, txm.maybeRetry(context.Background(), unconfirmedTx, RetryReasonExpired))
}
