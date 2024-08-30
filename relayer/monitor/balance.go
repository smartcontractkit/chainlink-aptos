package monitor

import (
	"context"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

// Config defines the balance monitor configuration.
type Config struct {
	BalancePollPeriod time.Duration
}

type BalanceClient interface {
	GetAccountBalance(addr string) (float64, error)
}

type BalanceMonitorOpts struct {
	ChainID         string
	ChainName       string
	BalanceCoinName string

	Config           Config
	Logger           logger.Logger
	Keystore         core.Keystore
	NewBalanceClient func() (BalanceClient, error)
}

// NewBalanceMonitor returns a balance monitoring services.Service which reports the TRX balance of all ks keys to prometheus.
func NewBalanceMonitor(opts BalanceMonitorOpts) services.Service {
	return newBalanceMonitor(opts)
}

func newBalanceMonitor(opts BalanceMonitorOpts) *balanceMonitor {
	return &balanceMonitor{
		cfg:  opts.Config,
		lggr: logger.Named(opts.Logger, "BalanceMonitor"),
		ks:   opts.Keystore,

		newReader: opts.NewBalanceClient,
		updateFn: func(acc string, balance float64) {
			promWTAccountBalance.WithLabelValues(acc, opts.ChainID, opts.ChainName, opts.BalanceCoinName).Set(balance)
		},

		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
}

type balanceMonitor struct {
	services.StateMachine
	cfg  Config
	lggr logger.Logger
	ks   core.Keystore

	// Returns a new BalanceClient
	newReader func() (BalanceClient, error)
	// Updates the balance metric
	updateFn func(acc string, balance float64) // overridable for testing

	reader BalanceClient

	stop services.StopChan
	done chan struct{}
}

func (m *balanceMonitor) Name() string {
	return m.lggr.Name()
}

func (m *balanceMonitor) Start(context.Context) error {
	return m.StartOnce(m.Name(), func() error {
		go m.start()
		return nil
	})
}

func (m *balanceMonitor) Close() error {
	return m.StopOnce(m.Name(), func() error {
		close(m.stop)
		<-m.done
		return nil
	})
}

func (m *balanceMonitor) HealthReport() map[string]error {
	return map[string]error{m.Name(): m.Healthy()}
}

func (m *balanceMonitor) start() {
	defer close(m.done)
	ctx, cancel := m.stop.NewCtx()
	defer cancel()

	tick := time.After(utils.WithJitter(m.cfg.BalancePollPeriod))
	for {
		select {
		case <-m.stop:
			return
		case <-tick:
			m.updateBalances(ctx)
			tick = time.After(utils.WithJitter(m.cfg.BalancePollPeriod))
		}
	}
}

func (b *balanceMonitor) getReader() (BalanceClient, error) {
	if b.reader == nil {
		var err error
		b.reader, err = b.newReader()
		if err != nil {
			return nil, err
		}
	}
	return b.reader, nil
}

func (b *balanceMonitor) updateBalances(ctx context.Context) {
	keys, err := b.ks.Accounts(ctx)
	if err != nil {
		b.lggr.Errorw("Failed to get keys", "err", err)
		return
	}
	if len(keys) == 0 {
		return
	}
	reader, err := b.getReader()
	if err != nil {
		b.lggr.Errorw("Failed to get client", "err", err)
		return
	}
	var gotSomeBals bool
	for _, k := range keys {
		// Check for shutdown signal, since Balance blocks and may be slow.
		select {
		case <-b.stop:
			return
		default:
		}
		balance, err := reader.GetAccountBalance(k)
		if err != nil {
			b.lggr.Errorw("Failed to get balance", "account", k, "err", err)
			continue
		}
		gotSomeBals = true
		b.updateFn(k, balance)
	}
	if !gotSomeBals {
		// Try a new client next time. // TODO: This is for multinode
		b.reader = nil
	}
}
