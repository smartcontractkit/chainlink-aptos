package aptos

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/chains"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

type Chain interface {
	types.ChainService

	ID() string
	Config() *config.TOMLConfig

	TxManager() *txm.AptosTxm
	GetClient() (*aptos.NodeClient, error)
}

type ChainOpts struct {
	Logger logger.Logger
	// the implementation used here needs to be co-ordinated with the aptos transaction manager keystore adapter
	KeyStore loop.Keystore
}

func (o *ChainOpts) Name() string {
	return o.Logger.Name()
}

func (o *ChainOpts) Validate() (err error) {
	required := func(s string) error {
		return fmt.Errorf("%s is required", s)
	}
	if o.Logger == nil {
		err = errors.Join(err, required("Logger"))
	}
	if o.KeyStore == nil {
		err = errors.Join(err, required("KeyStore"))
	}
	return
}

var _ Chain = (*chain)(nil)

type chain struct {
	starter utils.StartStopOnce

	id   string
	cfg  *config.TOMLConfig
	lggr logger.Logger

	// Sub-services
	txm            *txm.AptosTxm
	balanceMonitor services.Service
}

func NewChain(cfg *config.TOMLConfig, opts ChainOpts) (Chain, error) {
	if !cfg.IsEnabled() {
		return nil, fmt.Errorf("cannot create new chain with ID %s: chain is disabled", cfg.ChainID)
	}
	return newChain(cfg.ChainID, cfg, opts.KeyStore, opts.Logger)
}

func newChain(id string, cfg *config.TOMLConfig, loopKs loop.Keystore, lggr logger.Logger) (*chain, error) {
	lggr = logger.With(lggr, "chainID", id)

	// TEMP: fetch the first account in the store to use for transmissions to avoid having to specify it in TOML
	accounts, err := loopKs.Accounts(context.Background())
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("No aptos account available")
	}
	cfg.Chain.Workflow.PublicKey = accounts[0]

	ch := &chain{
		id:   id,
		cfg:  cfg,
		lggr: logger.Named(lggr, "Chain"),
	}

	getClient := func() (*aptos.NodeClient, error) {
		return ch.GetClient()
	}

	ch.txm, err = txm.New(lggr, loopKs, *cfg.TransactionManager, getClient)
	if err != nil {
		return nil, err
	}

	// Setup accounts balance monitor
	ch.balanceMonitor, err = monitor.NewAptosAccBalanceMonitor(monitor.AptosAccBalanceMonitorOpts{
		ChainID: ch.ID(),

		Config:    *ch.Config().BalanceMonitor,
		Logger:    lggr,
		Keystore:  loopKs,
		NewClient: getClient,
	})
	if err != nil {
		return nil, err
	}

	return ch, nil
}

func (c *chain) Name() string {
	return c.lggr.Name()
}

func (c *chain) Config() *config.TOMLConfig {
	return c.cfg
}

func (c *chain) TxManager() *txm.AptosTxm {
	return c.txm
}

func (c *chain) ChainID() string {
	return c.id
}

// GetClient returns a client, randomly selecting one from available and valid nodes
func (c *chain) GetClient() (*aptos.NodeClient, error) {
	var node *config.Node
	var err error
	var client *aptos.NodeClient
	nodes := c.cfg.Nodes
	if len(nodes) == 0 {
		return nil, errors.New("no nodes available")
	}
	// #nosec
	index := rand.Perm(len(nodes)) // list of node indexes to try
	for _, i := range index {
		node = nodes[i]
		// create client and check
		client, err = aptos.NewNodeClient(node.URL.String(), 0) // TODO: chainId
		// if error, try another node
		if err != nil {
			c.lggr.Warnw("failed to create node", "name", node.Name, "aptos-url", node.URL, "err", err.Error())
			continue
		}
		// if all checks passed, mark found and break loop
		break
	}
	// if no valid node found, exit with error
	if client == nil {
		return nil, errors.New("no node valid nodes available")
	}
	c.lggr.Debugw("Created client", "name", node.Name, "starknet-url", node.URL)
	return client, nil
}

func (c *chain) Start(ctx context.Context) error {
	return c.starter.StartOnce("Chain", func() error {
		c.lggr.Debug("Starting")
		c.lggr.Debug("Starting txm")
		c.lggr.Debug("Starting balance monitor")

		var ms services.MultiStart
		return ms.Start(ctx, c.txm, c.balanceMonitor)
	})
}

func (c *chain) Close() error {
	return c.starter.StopOnce("Chain", func() error {
		c.lggr.Debug("Stopping")
		c.lggr.Debug("Stopping txm")
		c.lggr.Debug("Stopping balance monitor")

		return services.CloseAll(c.txm, c.balanceMonitor)
	})
}

func (c *chain) Ready() error {
	return errors.Join(c.starter.Ready(), c.txm.Ready(), c.balanceMonitor.Ready())
}

func (c *chain) HealthReport() map[string]error {
	report := map[string]error{c.Name(): c.starter.Healthy()}
	services.CopyHealth(report, c.txm.HealthReport())
	services.CopyHealth(report, c.balanceMonitor.HealthReport())
	return report
}

func (c *chain) ID() string {
	return c.id
}

// LatestHead returns the latest head for the underlying chain.
func (c *chain) LatestHead(ctx context.Context) (types.Head, error) {
	return types.Head{}, errors.ErrUnsupported
}

// ChainService interface
func (c *chain) GetChainStatus(ctx context.Context) (types.ChainStatus, error) {
	toml, err := c.cfg.TOMLString()
	if err != nil {
		return types.ChainStatus{}, err
	}
	return types.ChainStatus{
		ID:      c.id,
		Enabled: c.cfg.IsEnabled(),
		Config:  toml,
	}, nil
}

func (c *chain) ListNodeStatuses(ctx context.Context, pageSize int32, pageToken string) (stats []types.NodeStatus, nextPageToken string, total int, err error) {
	return chains.ListNodeStatuses(int(pageSize), pageToken, c.listNodeStatuses)
}

func (c *chain) Transact(ctx context.Context, from, to string, amount *big.Int, balanceCheck bool) error {
	return errors.ErrUnsupported
}

func (c *chain) SendTx(ctx context.Context, from, to string, amount *big.Int, balanceCheck bool) error {
	return c.Transact(ctx, from, to, amount, balanceCheck)
}

// TODO BCF-2602 statuses are static for non-evm chain and should be dynamic
func (c *chain) listNodeStatuses(start, end int) ([]types.NodeStatus, int, error) {
	stats := make([]types.NodeStatus, 0)
	total := len(c.cfg.Nodes)
	if start >= total {
		return stats, total, chains.ErrOutOfRange
	}
	if end <= 0 || end > total {
		end = total
	}
	nodes := c.cfg.Nodes[start:end]
	for _, node := range nodes {
		stat, err := nodeStatus(node, c.ChainID())
		if err != nil {
			return stats, total, err
		}
		stats = append(stats, stat)
	}
	return stats, total, nil
}

func nodeStatus(n *config.Node, id string) (types.NodeStatus, error) {
	var s types.NodeStatus
	s.ChainID = id
	s.Name = *n.Name
	b, err := toml.Marshal(n)
	if err != nil {
		return types.NodeStatus{}, err
	}
	s.Config = string(b)
	return s, nil
}
