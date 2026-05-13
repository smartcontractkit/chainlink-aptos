package chain

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/chains"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/ratelimit"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	rtypes "github.com/smartcontractkit/chainlink-aptos/relayer/types"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

type Chain interface {
	types.ChainService

	ID() string
	Config() *config.TOMLConfig
	DataSource() sqlutil.DataSource

	TxManager() *txm.AptosTxm
	LogPoller() *logpoller.AptosLogPoller
	GetClient() (aptos.AptosRpcClient, error)
	KeyStore() loop.Keystore
}

type ChainOpts struct {
	Logger logger.Logger
	// the implementation used here needs to be co-ordinated with the aptos transaction manager keystore adapter
	KeyStore loop.Keystore
	DS       sqlutil.DataSource
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
	if o.DS == nil {
		err = errors.Join(err, required("DataSource"))
	}
	return
}

var _ Chain = (*chain)(nil)

type chain struct {
	starter commonutils.StartStopOnce

	id       string
	cfg      *config.TOMLConfig
	lggr     logger.Logger
	ds       sqlutil.DataSource
	keyStore loop.Keystore

	// clientCache caches a rate-limited Aptos client per node URL to avoid creating
	// a new NodeClient on every GetClient() call (port exhaustion with aptos-go-sdk v1.12+).
	// The write lock is held throughout creation so a burst of requests doesn't race to create.
	clientCacheMu sync.RWMutex
	clientCache   map[string]aptos.AptosRpcClient

	// Sub-services
	txm            *txm.AptosTxm
	logPoller      *logpoller.AptosLogPoller
	balanceMonitor services.Service
}

func NewChain(cfg *config.TOMLConfig, opts ChainOpts) (Chain, error) {
	if !cfg.IsEnabled() {
		return nil, fmt.Errorf("cannot create new chain with ID %s: chain is disabled", cfg.ChainID)
	}
	return newChain(cfg, opts.KeyStore, opts.Logger, opts.DS)
}

func newChain(cfg *config.TOMLConfig, loopKs loop.Keystore, lggr logger.Logger, ds sqlutil.DataSource) (*chain, error) {
	lggr = logger.With(lggr, "chainID", cfg.ChainID)

	// TEMP: fetch the first account in the store to use for transmissions to avoid having to specify it in TOML
	accounts, err := loopKs.Accounts(context.Background())
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, fmt.Errorf("No aptos account available")
	}

	_, err = strconv.ParseUint(cfg.ChainID, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid chain ID %s: could not parse as an integer: %w", cfg.ChainID, err)
	}

	if cfg.Chain.Workflow != nil {
		cfg.Chain.Workflow.PublicKey = accounts[0]
	}

	ch := &chain{
		id:         cfg.ChainID,
		cfg:        cfg,
		lggr:       logger.Named(lggr, "Chain"),
		ds:         ds,
		keyStore:   loopKs,
		clientCache: make(map[string]aptos.AptosRpcClient),
	}

	ch.txm, err = txm.New(lggr, loopKs, *cfg.TransactionManager, ch.GetClient, cfg.ChainID)
	if err != nil {
		return nil, err
	}

	ch.logPoller, err = logpoller.NewLogPoller(lggr, ch.chainInfo(), ch.GetClient, ds, cfg.LogPoller)
	if err != nil {
		return nil, fmt.Errorf("failed to create log poller: %w", err)
	}

	// Setup accounts balance monitor
	ch.balanceMonitor, err = monitor.NewBalanceMonitor(monitor.BalanceMonitorOpts{
		ChainInfo: ch.chainInfo(),

		Config:    *cfg.BalanceMonitor,
		Logger:    lggr,
		Keystore:  loopKs,
		NewClient: ch.GetClient,
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

func (c *chain) LogPoller() *logpoller.AptosLogPoller {
	return c.logPoller
}

func (c *chain) DataSource() sqlutil.DataSource {
	return c.ds
}

func (c *chain) ChainID() string {
	return c.id
}

func (c *chain) KeyStore() loop.Keystore {
	return c.keyStore
}

// GetClient returns a client, randomly selecting one from available and valid nodes.
// Clients are cached per node URL. Uses http.DefaultClient so all NodeClients share
// the process-wide default transport (avoids port exhaustion with aptos-go-sdk v1.12+).
// The write lock is held throughout creation so a burst of requests cannot race to
// create multiple clients for the same URL (last writer wins / leaked clients).
func (c *chain) GetClient() (aptos.AptosRpcClient, error) {
	nodes := c.cfg.Nodes
	if len(nodes) == 0 {
		return nil, errors.New("no nodes available")
	}

	// #nosec
	index := rand.Perm(len(nodes))

	// Fast path: try cached client (read lock only).
	for _, i := range index {
		node := nodes[i]
		urlStr := node.URL.String()
		c.clientCacheMu.RLock()
		cached := c.clientCache[urlStr]
		c.clientCacheMu.RUnlock()
		if cached != nil {
			chainId, err := cached.GetChainId()
			if err != nil {
				c.clientCacheMu.Lock()
				delete(c.clientCache, urlStr)
				c.clientCacheMu.Unlock()
				continue
			}
			chainInfo := c.chainInfo()
			if strconv.FormatUint(uint64(chainId), 10) == chainInfo.ChainID {
				return cached, nil
			}
			c.clientCacheMu.Lock()
			delete(c.clientCache, urlStr)
			c.clientCacheMu.Unlock()
		}
	}

	// Slow path: create and cache. Hold lock for entire creation so only one goroutine
	// creates per URL (avoids race where burst of requests all create, last writer wins).
	c.clientCacheMu.Lock()
	defer c.clientCacheMu.Unlock()
	for _, i := range index {
		node := nodes[i]
		urlStr := node.URL.String()
		if c.clientCache[urlStr] != nil {
			return c.clientCache[urlStr], nil
		}
		client, err := aptos.NewNodeClientWithHttpClient(urlStr, 0, http.DefaultClient)
		if err != nil {
			c.lggr.Warnw("failed to create node", "name", node.Name, "aptos-url", node.URL, "err", err)
			continue
		}
		chainId, err := client.GetChainId()
		if err != nil {
			c.lggr.Errorw("failed to fetch chain id", "name", node.Name, "err", err)
			continue
		}
		chainInfo := c.chainInfo()
		if strconv.FormatUint(uint64(chainId), 10) != chainInfo.ChainID {
			c.lggr.Errorw("unexpected chain id", "name", node.Name, "localChainId", chainInfo.ChainID, "remoteChainId", chainId)
			continue
		}
		rateLimitedClient := ratelimit.NewRateLimitedClient(client,
			chainInfo,
			urlStr,
			500,            // max requests in-flight
			30*time.Second, // timeout
		)
		c.clientCache[urlStr] = rateLimitedClient
		c.lggr.Debugw("Created and cached client", "name", node.Name, "url", node.URL)
		return rateLimitedClient, nil
	}
	return nil, errors.New("no valid nodes available")
}

func (c *chain) Start(ctx context.Context) error {
	return c.starter.StartOnce("Chain", func() error {
		c.lggr.Debug("Starting")
		c.lggr.Debug("Starting txm")
		c.lggr.Debug("Starting logPoller")
		c.lggr.Debug("Starting balance monitor")

		var ms services.MultiStart
		return ms.Start(ctx, c.txm, c.logPoller, c.balanceMonitor)
	})
}

func (c *chain) Close() error {
	return c.starter.StopOnce("Chain", func() error {
		c.lggr.Debug("Stopping")
		c.lggr.Debug("Stopping txm")
		c.lggr.Debug("Stopping logPoller")
		c.lggr.Debug("Stopping balance monitor")

		return services.CloseAll(c.txm, c.logPoller, c.balanceMonitor)
	})
}

func (c *chain) Ready() error {
	return errors.Join(c.starter.Ready(), c.txm.Ready(), c.logPoller.Ready(), c.balanceMonitor.Ready())
}

func (c *chain) HealthReport() map[string]error {
	report := map[string]error{c.Name(): c.starter.Healthy()}
	services.CopyHealth(report, c.txm.HealthReport())
	services.CopyHealth(report, c.logPoller.HealthReport())
	services.CopyHealth(report, c.balanceMonitor.HealthReport())
	return report
}

func (c *chain) ID() string {
	return c.id
}

func (c *chain) GetChainInfo(ctx context.Context) (types.ChainInfo, error) {
	_ = ctx
	return types.ChainInfo{
		FamilyName:      config.ChainFamilyName,
		ChainID:         c.id,
		NetworkName:     c.cfg.NetworkName,
		NetworkNameFull: c.cfg.NetworkNameFull,
	}, nil
}

// LatestHead returns the latest head for the underlying chain.
// TODO: should be replaced with a head tracker component
func (c *chain) LatestHead(ctx context.Context) (types.Head, error) {
	client, err := c.GetClient()
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to get client: %w", err)
	}

	// Try to get the latest block height and block by height
	info, err := client.Info()
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to get chain info: %w", err)
	}

	withTransactions := false
	block, err := client.BlockByHeight(info.BlockHeight(), withTransactions)
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to get block by height: %w", err)
	}

	// Map to common Head type
	hash, err := utils.DecodeHexRelaxed(block.BlockHash)
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to decode block hash: %w", err)
	}

	return types.Head{
		Hash:   hash,
		Height: strconv.FormatUint(block.BlockHeight, 10),
		// block.BlockTimestamp is the Unix timestamp of the block, in microseconds, may not be set for block 0
		// Divide by 1000000 to convert to seconds
		Timestamp: block.BlockTimestamp / 1000000,
	}, nil
}

// FinalizedHead returns the latest finalized head for the underlying chain.
// Aptos has single-shot finality, so the finalized head is the latest head.
func (c *chain) FinalizedHead(ctx context.Context) (types.Head, error) {
	return c.LatestHead(ctx)
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
	// TODO: this should be (?) hooked into ChainWriter API
	return errors.ErrUnsupported
}

func (c *chain) Replay(ctx context.Context, fromBlock string, args map[string]any) error {
	return errors.ErrUnsupported
}

// TODO BCF-2602 statuses are static for non-evm chain and should be dynamic
func (c *chain) listNodeStatuses(start, end int) ([]types.NodeStatus, int, error) {
	stats := make([]types.NodeStatus, 0, end-start)
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
	if n == nil {
		return types.NodeStatus{}, errors.New("nil node passed for node status")
	}
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

func (c *chain) chainInfo() rtypes.ChainInfo {
	return rtypes.ChainInfo{
		ChainFamilyName: config.ChainFamilyName,
		ChainID:         c.id,
		NetworkName:     c.cfg.NetworkName,
		NetworkNameFull: c.cfg.NetworkNameFull,
	}
}
