package txm

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/metrics"
)

var (
	// broadcasted transactions
	promAptosTxmBroadcastedTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_broadcasted",
		Help: "Number of transactions successfully submitted to the mempool",
	}, []string{"chainID"})

	// successful transactions
	promAptosTxmSuccessTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_success",
		Help: "Number of transactions confirmed successfully on-chain",
	}, []string{"chainID"})
	promAptosTxmFinalizedTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_finalized",
		Help: "Number of transactions that reached finalized status",
	}, []string{"chainID"})

	// inflight transactions
	promAptosTxmPendingTxs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aptos_txm_tx_pending",
		Help: "Number of unconfirmed transactions currently in-flight",
	}, []string{"chainID"})

	// error cases
	promAptosTxmErrorTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_error",
		Help: "Total number of transaction errors across all failure modes",
	}, []string{"chainID"})
	promAptosTxmRevertTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_error_revert",
		Help: "Number of transactions confirmed but unsuccessful on-chain (e.g. out of gas)",
	}, []string{"chainID"})
	promAptosTxmRejectTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_error_reject",
		Help: "Number of transactions rejected by the RPC after exhausting submit retries",
	}, []string{"chainID"})
	promAptosTxmDropTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_error_drop",
		Help: "Number of transactions that expired without being committed on-chain",
	}, []string{"chainID"})
	promAptosTxmRetryTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_retry",
		Help: "Number of transaction retries triggered (out-of-gas or expired)",
	}, []string{"chainID"})
)

type aptosTxmMetrics struct {
	metrics.Labeler
	chainID string

	broadcastedTxs metric.Int64Counter
	successTxs     metric.Int64Counter
	finalizedTxs   metric.Int64Counter
	pendingTxs     metric.Int64Gauge
	errorTxs       metric.Int64Counter
	revertTxs      metric.Int64Counter
	rejectTxs      metric.Int64Counter
	dropTxs        metric.Int64Counter
	retryTxs       metric.Int64Counter
}

func newAptosTxmMetrics(chainID string) (*aptosTxmMetrics, error) {
	m := beholder.GetMeter()

	broadcastedTxs, err := m.Int64Counter("aptos_txm_tx_broadcasted")
	if err != nil {
		return nil, fmt.Errorf("failed to register broadcasted txs counter: %w", err)
	}

	successTxs, err := m.Int64Counter("aptos_txm_tx_success")
	if err != nil {
		return nil, fmt.Errorf("failed to register success txs counter: %w", err)
	}

	finalizedTxs, err := m.Int64Counter("aptos_txm_tx_finalized")
	if err != nil {
		return nil, fmt.Errorf("failed to register finalized txs counter: %w", err)
	}

	pendingTxs, err := m.Int64Gauge("aptos_txm_tx_pending")
	if err != nil {
		return nil, fmt.Errorf("failed to register pending txs gauge: %w", err)
	}

	errorTxs, err := m.Int64Counter("aptos_txm_tx_error")
	if err != nil {
		return nil, fmt.Errorf("failed to register error txs counter: %w", err)
	}

	revertTxs, err := m.Int64Counter("aptos_txm_tx_error_revert")
	if err != nil {
		return nil, fmt.Errorf("failed to register revert txs counter: %w", err)
	}

	rejectTxs, err := m.Int64Counter("aptos_txm_tx_error_reject")
	if err != nil {
		return nil, fmt.Errorf("failed to register reject txs counter: %w", err)
	}

	dropTxs, err := m.Int64Counter("aptos_txm_tx_error_drop")
	if err != nil {
		return nil, fmt.Errorf("failed to register drop txs counter: %w", err)
	}

	retryTxs, err := m.Int64Counter("aptos_txm_tx_retry")
	if err != nil {
		return nil, fmt.Errorf("failed to register retry txs counter: %w", err)
	}

	return &aptosTxmMetrics{
		chainID: chainID,
		Labeler: metrics.NewLabeler().With("chainID", chainID),

		broadcastedTxs: broadcastedTxs,
		successTxs:     successTxs,
		finalizedTxs:   finalizedTxs,
		pendingTxs:     pendingTxs,
		errorTxs:       errorTxs,
		revertTxs:      revertTxs,
		rejectTxs:      rejectTxs,
		dropTxs:        dropTxs,
		retryTxs:       retryTxs,
	}, nil
}

func (m *aptosTxmMetrics) getOtelAttributes() []attribute.KeyValue {
	return beholder.OtelAttributes(m.Labels).AsStringAttributes()
}

func (m *aptosTxmMetrics) IncrementBroadcastedTxs(ctx context.Context) {
	promAptosTxmBroadcastedTxs.WithLabelValues(m.chainID).Add(1)
	m.broadcastedTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementSuccessTxs(ctx context.Context) {
	promAptosTxmSuccessTxs.WithLabelValues(m.chainID).Add(1)
	m.successTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementFinalizedTxs(ctx context.Context) {
	promAptosTxmFinalizedTxs.WithLabelValues(m.chainID).Add(1)
	m.finalizedTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) SetPendingTxs(ctx context.Context, count int) {
	promAptosTxmPendingTxs.WithLabelValues(m.chainID).Set(float64(count))
	m.pendingTxs.Record(ctx, int64(count), metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementErrorTxs(ctx context.Context) {
	promAptosTxmErrorTxs.WithLabelValues(m.chainID).Add(1)
	m.errorTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementRevertTxs(ctx context.Context) {
	promAptosTxmRevertTxs.WithLabelValues(m.chainID).Add(1)
	m.revertTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementRejectTxs(ctx context.Context) {
	promAptosTxmRejectTxs.WithLabelValues(m.chainID).Add(1)
	m.rejectTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementDropTxs(ctx context.Context) {
	promAptosTxmDropTxs.WithLabelValues(m.chainID).Add(1)
	m.dropTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}

func (m *aptosTxmMetrics) IncrementRetryTxs(ctx context.Context) {
	promAptosTxmRetryTxs.WithLabelValues(m.chainID).Add(1)
	m.retryTxs.Add(ctx, 1, metric.WithAttributes(m.getOtelAttributes()...))
}
