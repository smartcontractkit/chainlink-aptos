package monitor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
)

// Define a new gauge metric for account balance
type GaugeAccBalance struct {
	// write_target_account_balance
	gauge metric.Float64Gauge
}

func NewGaugeAccBalance(unitStr string) (*GaugeAccBalance, error) {
	// TODO: group this under 'chain' (parent service) not under 'write_target' (original plan)
	name := "write_target_account_balance"
	description := "Balance for configured WT account"
	gauge, err := beholder.GetMeter().Float64Gauge(name, metric.WithUnit(unitStr), metric.WithDescription(description))
	if err != nil {
		return nil, fmt.Errorf("failed to create new gauge %s: %+w", name, err)
	}
	return &GaugeAccBalance{gauge}, nil
}

func (g *GaugeAccBalance) Record(ctx context.Context, balance float64, account, networkChainID, networkName string) {
	oAttrs := metric.WithAttributeSet(g.GetAttributes(account, networkChainID, networkName))
	g.gauge.Record(ctx, balance, oAttrs)
}

func (g *GaugeAccBalance) GetAttributes(account, networkChainID, networkName string) attribute.Set {
	return attribute.NewSet(
		attribute.String("account", account),
		attribute.String("network_chain_id", networkChainID),
		attribute.String("network_name", networkName),
	)
}
