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

// Error reason constants for the aptos_txm_tx_error metric.
const (
	ErrorReasonSequenceNumber = "sequence_number"
	ErrorReasonStoreCreate    = "store_create"
	ErrorReasonSimulation     = "simulation"
	ErrorReasonSigning        = "signing"
	ErrorReasonNoHash         = "no_hash"
	ErrorReasonStoreAdd       = "store_add"
	ErrorReasonUnknownSubmit  = "unknown_submit"
	ErrorReasonMaxRetries     = "max_retries"
	ErrorReasonRevert         = "revert"
	ErrorReasonTypeAssertion  = "type_assertion"
	ErrorReasonUnexpectedType = "unexpected_type"
	ErrorReasonExpiredConfirm = "expired_confirm"
	ErrorReasonDrop           = "drop"
)

var (
	promAptosTxmBroadcastedTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_broadcasted",
		Help: "Number of transactions successfully submitted to the mempool",
	}, []string{"chainID"})

	promAptosTxmSuccessTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_success",
		Help: "Number of transactions confirmed successfully on-chain",
	}, []string{"chainID"})

	promAptosTxmFinalizedTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_finalized",
		Help: "Number of transactions that reached finalized status",
	}, []string{"chainID"})

	promAptosTxmPendingTxs = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "aptos_txm_tx_pending",
		Help: "Number of unconfirmed transactions currently in-flight",
	}, []string{"chainID"})

	promAptosTxmErrorTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_error",
		Help: "Transaction errors by reason",
	}, []string{"chainID", "reason"})

	promAptosTxmRetryTxs = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "aptos_txm_tx_retry",
		Help: "Transaction retries by reason",
	}, []string{"chainID", "reason"})
)

type aptosTxmMetrics struct {
	metrics.Labeler
	chainID string

	broadcastedTxs metric.Int64Counter
	successTxs     metric.Int64Counter
	finalizedTxs   metric.Int64Counter
	pendingTxs     metric.Int64Gauge
	errorTxs       metric.Int64Counter
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

func (m *aptosTxmMetrics) IncrementErrorTxs(ctx context.Context, reason string) {
	promAptosTxmErrorTxs.WithLabelValues(m.chainID, reason).Add(1)
	otelAttrs := append(m.getOtelAttributes(), attribute.String("reason", reason))
	m.errorTxs.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
}

func (m *aptosTxmMetrics) IncrementRetryTxs(ctx context.Context, reason string) {
	promAptosTxmRetryTxs.WithLabelValues(m.chainID, reason).Add(1)
	otelAttrs := append(m.getOtelAttributes(), attribute.String("reason", reason))
	m.retryTxs.Add(ctx, 1, metric.WithAttributes(otelAttrs...))
}
