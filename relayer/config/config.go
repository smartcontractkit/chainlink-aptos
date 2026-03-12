package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/config"

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
