package chain

import (
	"context"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	frameworkmetrics "github.com/smartcontractkit/chainlink-framework/metrics"
	"github.com/smartcontractkit/chainlink-framework/multinode"
)

// ServiceRPCClient is the subset of the Aptos SDK used by the multinode adapter and the aptos
// service layer. Keeping it narrow decouples the relayer from churn in the full SDK interface
// and makes mocking straightforward.
type ServiceRPCClient interface {
	Info() (aptos.NodeInfo, error)
	GetChainId() (uint8, error)
	NodeAPIHealthCheck(durationSecs ...uint64) (api.HealthCheckResponse, error)
	Account(address aptos.AccountAddress, ledgerVersion ...uint64) (aptos.AccountInfo, error)
	AccountAPTBalance(address aptos.AccountAddress, ledgerVersion ...uint64) (uint64, error)
	View(payload *aptos.ViewPayload, ledgerVersion ...uint64) ([]any, error)
	TransactionByHash(txnHash string) (*api.Transaction, error)
	AccountTransactions(address aptos.AccountAddress, start *uint64, limit *uint64) ([]*api.CommittedTransaction, error)
}

// Head is the multinode head for Aptos. Aptos blocks have single-shot finality (committed
// blocks are final, no reorgs), so there is a single head notion: the latest block is also
// the finalized block. Difficulty/total-difficulty are PoW concepts and are always nil.
type Head struct {
	Height uint64
}

func (h *Head) BlockNumber() int64 {
	if !h.IsValid() {
		return 0
	}
	return int64(h.Height)
}

func (h *Head) BlockDifficulty() *big.Int    { return nil }
func (h *Head) GetTotalDifficulty() *big.Int { return nil }

func (h *Head) IsValid() bool { return h != nil && h.Height > 0 }

// MultiNodeClient embeds *multinode.RPCClientBase, which supplies the head/finalized-head
// subscriptions (via polling) and subscription bookkeeping. It also embeds ServiceRPCClient
// which promotes the narrow set of domain methods needed by the aptos service.
type MultiNodeClient struct {
	*multinode.RPCClientBase[*Head]

	ServiceRPCClient
	lggr logger.Logger
}

var _ multinode.RPCClient[multinode.StringID, *Head] = (*MultiNodeClient)(nil)

// NewMultiNodeClient builds an adapter around the Aptos RPC at url. cfg supplies the
// head/finalized poll intervals consumed by RPCClientBase.
func NewMultiNodeClient(
	url string,
	cfg multinode.RPCClientBaseConfig,
	requestTimeout time.Duration,
	lggr logger.Logger,
	rpcMetrics frameworkmetrics.RPCClientMetrics,
) (*MultiNodeClient, error) {
	nodeClient, err := aptos.NewNodeClientWithHttpClient(url, 0, &http.Client{Timeout: requestTimeout})
	if err != nil {
		return nil, fmt.Errorf("failed to create aptos node client for %s: %w", url, err)
	}

	c := &MultiNodeClient{
		ServiceRPCClient: nodeClient,
		lggr:             logger.Named(lggr, "MultiNodeClient"),
	}
	c.RPCClientBase = multinode.NewRPCClientBase[*Head](
		cfg, requestTimeout, lggr,
		c.latestBlock,
		c.latestFinalizedBlock,
		url,
		false, // not send-only
		rpcMetrics,
	)
	return c, nil
}

// Dial validates reachability of the endpoint. The SDK client is HTTP and does not hold a
// persistent connection, so a successful health probe stands in for a dial handshake.
func (c *MultiNodeClient) Dial(ctx context.Context) error {
	_, err := c.NodeAPIHealthCheck()
	if err != nil {
		return fmt.Errorf("aptos rpc dial/health check failed: %w", err)
	}
	return nil
}

// ChainID returns the Aptos chain ID as a StringID (e.g. "2" for testnet). This matches
// the config ChainID form so node chain-ID verification can be enabled.
func (c *MultiNodeClient) ChainID(_ context.Context) (multinode.StringID, error) {
	chainID, err := c.GetChainId()
	if err != nil {
		return "", fmt.Errorf("failed to get chain id: %w", err)
	}
	return multinode.StringID(strconv.FormatUint(uint64(chainID), 10)), nil
}

// ClientVersion doubles as the periodic liveness probe; it returns an error when the RPC is
// unreachable, which the node lifecycle treats as a health failure.
func (c *MultiNodeClient) ClientVersion(_ context.Context) (string, error) {
	info, err := c.Info()
	if err != nil {
		return "", err
	}
	return info.GitHash, nil
}

// IsSyncing is always false: Aptos RPC does not expose a backfill/sync state that blocks
// reads, and lagging nodes are caught by head-based out-of-sync detection instead.
func (c *MultiNodeClient) IsSyncing(_ context.Context) (bool, error) { return false, nil }

// latestBlock / latestFinalizedBlock back the RPCClientBase head subscriptions. They are
// identical because the latest committed block is already final on Aptos.
func (c *MultiNodeClient) latestBlock(_ context.Context) (*Head, error) {
	info, err := c.Info()
	if err != nil {
		return nil, err
	}
	return &Head{Height: info.BlockHeight()}, nil
}

func (c *MultiNodeClient) latestFinalizedBlock(ctx context.Context) (*Head, error) {
	return c.latestBlock(ctx)
}

// Close tears down the framework subscriptions. The underlying SDK client is HTTP-only
// and has no persistent connection to close.
func (c *MultiNodeClient) Close() {
	c.RPCClientBase.Close()
}
