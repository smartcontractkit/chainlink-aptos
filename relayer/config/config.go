package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/config"
	mncfg "github.com/smartcontractkit/chainlink-framework/multinode/config"

	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target"
)

// Name of the chain family (e.g., "ethereum", "solana", "aptos")
const ChainFamilyName = "aptos"

var DefaultConfigSet = ConfigSet{
	TransactionManager: txm.DefaultConfigSet,
	LogPoller:          logpoller.DefaultConfigSet,
	BalanceMonitor:     monitor.DefaultBalanceConfig,
	WriteTargetCap:     write_target.DefaultConfigSet,
}

type ConfigSet struct { //nolint:revive
	TransactionManager txm.Config
	LogPoller          logpoller.Config
	BalanceMonitor     monitor.GenericBalanceConfig
	WriteTargetCap     write_target.Config
}

type WorkflowConfig struct {
	ForwarderAddress string
	// FromAddress      string
	PublicKey string
}

type Chain struct {
	TransactionManager *txm.Config                  `toml:"TransactionManager"`
	LogPoller          *logpoller.Config             `toml:"LogPoller"`
	BalanceMonitor     *monitor.GenericBalanceConfig `toml:"BalanceMonitor"`
	WriteTargetCap     *write_target.Config          `toml:"WriteTargetCap"`
	Workflow           *WorkflowConfig               `toml:"Workflow"`
}

type Node struct {
	Name *string
	URL  *config.URL
	// Order is the node priority used as a tiebreak by the multinode selector (lower wins on
	// equal head). Defaults to 0 when unset.
	Order *int32 `toml:"Order"`
}

func (n *Node) ValidateConfig() (err error) {
	if n.Name == nil {
		err = errors.Join(err, config.ErrMissing{Name: "Name", Msg: "required for all nodes"})
	} else if *n.Name == "" {
		err = errors.Join(err, config.ErrEmpty{Name: "Name", Msg: "required for all nodes"})
	}

	if n.URL == nil {
		err = errors.Join(err, config.ErrMissing{Name: "URL", Msg: "required for all nodes"})
	}

	return
}

type TOMLConfig struct {
	// Do not access directly. Use [IsEnabled]
	Enabled *bool

	// Chain configuration
	ChainID         string
	NetworkName     string
	NetworkNameFull string

	// Chain-specific components configuration
	Chain

	Nodes Nodes

	// MultiNode configures RPC node selection, health checking, and failover. Omitted fields
	// are filled by SetMultiNodeDefaults. See chainlink-framework/multinode.
	MultiNode mncfg.MultiNodeConfig `toml:"MultiNode"`

	// RequestTimeout bounds each individual Aptos RPC call (and the underlying HTTP client
	// timeout). Defaults to DefaultRequestTimeout when unset.
	RequestTimeout *config.Duration `toml:"RequestTimeout"`
}

// DefaultRequestTimeout bounds each individual Aptos RPC call when RequestTimeout is unset.
const DefaultRequestTimeout = 30 * time.Second

// SetMultiNodeDefaults fills any unset MultiNode field with an Aptos-appropriate default. The
// framework's config accessors dereference these pointers directly, so every field consumed by
// the node/multinode lifecycle must be non-nil. Tuned to Aptos's ~1-2s block time and its
// single-finality model (a committed block is final: no reorgs).
func (c *TOMLConfig) SetMultiNodeDefaults() {
	m := &c.MultiNode.MultiNode
	setDefault(&m.Enabled, true)
	setDefault(&m.PollFailureThreshold, uint32(5))
	setDefault(&m.PollInterval, *config.MustNewDuration(5*time.Second))
	setDefault(&m.SelectionMode, "HighestHead")
	setDefault(&m.SyncThreshold, uint32(5))
	setDefault(&m.NodeIsSyncingEnabled, false)
	setDefault(&m.LeaseDuration, *config.MustNewDuration(0))
	// Poll heads slightly faster than the ~1-2s block time so out-of-sync nodes are detected
	setDefault(&m.NewHeadsPollInterval, *config.MustNewDuration(2*time.Second))
	setDefault(&m.FinalizedBlockPollInterval, *config.MustNewDuration(2*time.Second))
	setDefault(&m.EnforceRepeatableRead, false)
	setDefault(&m.DeathDeclarationDelay, *config.MustNewDuration(20*time.Second))
	setDefault(&m.VerifyChainID, true)
	setDefault(&m.NodeNoNewHeadsThreshold, *config.MustNewDuration(15*time.Second))
	// NoNewFinalizedHeadsThreshold is read unconditionally by the node lifecycle even though
	// the finalized-head subscription is disabled (FinalityTagEnabled=false); keep it non-nil.
	setDefault(&m.NoNewFinalizedHeadsThreshold, *config.MustNewDuration(15*time.Second))
	// Aptos blocks are final at commit: derive "finalized" as latest (FinalityDepth=0) and
	// never run the finalized-head subscription (FinalityTagEnabled=false).
	setDefault(&m.FinalityDepth, uint32(0))
	setDefault(&m.FinalityTagEnabled, false)
	setDefault(&m.FinalizedBlockOffset, uint32(0))
	setDefault(&c.RequestTimeout, *config.MustNewDuration(DefaultRequestTimeout))
}

func setDefault[T any](p **T, val T) {
	if *p == nil {
		v := val
		*p = &v
	}
}

// applyDefaults ensures all component configs are non-nil and fully populated.
// For absent TOML sections (nil pointers), creates empty configs.
// Calls Resolve() on each to fill nil fields from per-package defaults.
func (cfg *TOMLConfig) applyDefaults() {
	if cfg.TransactionManager == nil {
		cfg.TransactionManager = &txm.Config{}
	}
	cfg.TransactionManager.Resolve()

	if cfg.LogPoller == nil {
		cfg.LogPoller = &logpoller.Config{}
	}
	cfg.LogPoller.Resolve()

	if cfg.BalanceMonitor == nil {
		cfg.BalanceMonitor = &monitor.GenericBalanceConfig{}
	}
	cfg.BalanceMonitor.Resolve()

	if cfg.WriteTargetCap == nil {
		cfg.WriteTargetCap = &write_target.Config{}
	}
	cfg.WriteTargetCap.Resolve()

	cfg.SetMultiNodeDefaults()

	// Set network name defaults
	if cfg.NetworkName == "" {
		network, err := GetNetworkConfig(cfg.ChainID)
		if err == nil {
			cfg.NetworkName = network.Name
		} else {
			cfg.NetworkName = "unknown"
		}
	}

	if cfg.NetworkNameFull == "" {
		cfg.NetworkNameFull = fmt.Sprintf("%s-%s", ChainFamilyName, cfg.NetworkName)
	}
}

// NewDecodedTOMLConfig decodes the rawConfig as (Aptos) TOML, merges with
// defaults, and validates. Fields absent from the TOML get default values;
// fields explicitly set (including to zero) are preserved as-is.
func NewDecodedTOMLConfig(rawConfig string) (*TOMLConfig, error) {
	d := toml.NewDecoder(strings.NewReader(rawConfig))
	d.DisallowUnknownFields()

	var cfg TOMLConfig
	if err := d.Decode(&cfg); err != nil {
		return &TOMLConfig{}, fmt.Errorf("failed to decode config toml: %w:\n\t%s", err, rawConfig)
	}

	cfg.applyDefaults()

	if err := cfg.ValidateConfig(); err != nil {
		return &TOMLConfig{}, fmt.Errorf("invalid aptos config: %w", err)
	}

	if !cfg.IsEnabled() {
		return &TOMLConfig{}, fmt.Errorf("cannot create new chain with ID %s: config is disabled", cfg.ChainID)
	}

	return &cfg, nil
}

func (c *TOMLConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

func (c *TOMLConfig) ValidateConfig() (err error) {
	if c.ChainID == "" {
		err = errors.Join(err, config.ErrEmpty{Name: "ChainID", Msg: "required for all chains"})
	}

	// If network name is set, ensure it matches a known network if chain ID is known
	if c.NetworkName != "" {
		var network aptos.NetworkConfig
		network, err = GetNetworkConfig(c.ChainID)
		if err == nil && c.NetworkName != network.Name {
			err = errors.Join(err, config.ErrInvalid{Name: "NetworkName", Value: c.NetworkName, Msg: fmt.Sprintf("does not match known network (%s) for chain ID", network.Name)})
		}
	}

	if len(c.Nodes) == 0 {
		err = errors.Join(err, config.ErrMissing{Name: "Nodes", Msg: "must have at least one node"})
	} else {
		for _, node := range c.Nodes {
			err = errors.Join(err, node.ValidateConfig())
		}
	}

	return
}

func (c *TOMLConfig) TOMLString() (string, error) {
	b, err := toml.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type Nodes []*Node
