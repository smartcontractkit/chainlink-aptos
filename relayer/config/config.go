package config

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-aptos/relayer/logpoller"
	"github.com/smartcontractkit/chainlink-aptos/relayer/monitor"
	"github.com/smartcontractkit/chainlink-aptos/relayer/write_target"
	"github.com/smartcontractkit/chainlink-common/pkg/config"
	"github.com/smartcontractkit/chainlink-common/pkg/config/configtest"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
)

// Name of the chain family (e.g., "ethereum", "solana", "aptos")
const ChainFamilyName = "aptos"

var defaults TOMLConfig

func init() {
	if err := configtest.DocDefaultsOnly(strings.NewReader(docsTOML), &defaults, config.DecodeTOML); err != nil {
		log.Fatalf("Failed to initialize defaults from docs: %v", err)
	}
}

func Defaults() (c TOMLConfig) {
	c.SetFrom(&defaults)
	return
}

type WorkflowConfig struct {
	ForwarderAddress string
	// FromAddress      string
	PublicKey string
}

type Chain struct {
	TransactionManager *TxmConfig
	LogPoller          *logpoller.Config
	BalanceMonitor     *monitor.GenericBalanceConfig
	WriteTargetCap     *write_target.Config
	Workflow           *WorkflowConfig
}

type TxmConfig struct {
	BroadcastChanSize uint
	ConfirmPollSecs   *uint // Deprecated: use ConfirmPoll
	ConfirmPoll       *config.Duration

	DefaultMaxGasAmount uint64
	MaxSimulateAttempts uint

	MaxSubmitRetryAttempts uint
	SubmitDelayDuration    *config.Duration
	TxExpirationSecs       *uint64 // Deprecated: use TxExpiration
	TxExpiration           *config.Duration
	MaxTxRetryAttempts     uint64
	PruneIntervalSecs      *uint64 // Deprecated: use PruneInterval
	PruneInterval          *config.Duration
	PruneTxExpirationSecs  *uint64 // Deprecated: use PruneTxExpiration
	PruneTxExpiration      *config.Duration
}

func (c *TxmConfig) ValidateConfig() (err error) {
	if c.ConfirmPollSecs != nil && c.ConfirmPoll != nil {
		err = errors.Join(err, errors.New("only one of ConfirmPollSecs and Confirm may be set"))
	} else if c.ConfirmPollSecs != nil {
		d, err2 := config.NewDuration(time.Duration(*c.ConfirmPollSecs) * time.Second)
		if err2 != nil {
			err = errors.Join(err, fmt.Errorf("ConfirmPollSecs must be a positive number: %w", err2))
		}
		c.ConfirmPoll = &d
	}
	if c.TxExpirationSecs != nil && c.TxExpiration != nil {
		err = errors.Join(err, errors.New("only one of TxExpirationSecs and TxExpiration may be set"))
	} else if c.TxExpirationSecs != nil {
		d, err2 := config.NewDuration(time.Duration(*c.TxExpirationSecs) * time.Second)
		if err2 != nil {
			err = errors.Join(err, fmt.Errorf("TxExpirationSecs must be a positive number: %w", err2))
		}
		c.TxExpiration = &d
	}
	if c.PruneIntervalSecs != nil && c.PruneInterval != nil {
		err = errors.Join(err, errors.New("only one of PruneIntervalSecs and PruneInterval may be set"))
	} else if c.PruneIntervalSecs != nil {
		d, err2 := config.NewDuration(time.Duration(*c.PruneIntervalSecs) * time.Second)
		if err2 != nil {
			err = errors.Join(err, fmt.Errorf("PruneIntervalSecs must be a positive number: %w", err2))
		}
		c.PruneInterval = &d
	}
	if c.PruneTxExpirationSecs != nil && c.PruneTxExpiration != nil {
		err = errors.Join(err, errors.New("only one of PruneTxExpirationSecs and PruneTxExpiration may be set"))
	} else if c.PruneTxExpirationSecs != nil {
		d, err2 := config.NewDuration(time.Duration(*c.PruneTxExpirationSecs) * time.Second)
		if err2 != nil {
			err = errors.Join(err, fmt.Errorf("PruneTxExpirationSecs must be a positive number: %w", err2))
		}
		c.PruneTxExpiration = &d
	}
	return
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
	ChainID         *string
	NetworkName     *string
	NetworkNameFull *string

	// Chain-specific components configuration
	Chain

	Nodes Nodes
}

// decodeConfig decodes the rawConfig as (Aptos) TOML and sets default values
func NewDecodedTOMLConfig(rawConfig string) (*TOMLConfig, error) {
	d := toml.NewDecoder(strings.NewReader(rawConfig))
	d.DisallowUnknownFields()

	var cfg TOMLConfig
	if err := d.Decode(&cfg); err != nil {
		return &TOMLConfig{}, fmt.Errorf("failed to decode config toml: %w:\n\t%s", err, rawConfig)
	}

	if err := cfg.ValidateConfig(); err != nil {
		return &TOMLConfig{}, fmt.Errorf("invalid aptos config: %w", err)
	}

	if !cfg.IsEnabled() {
		return &TOMLConfig{}, fmt.Errorf("cannot create new chain with ID %s: config is disabled", cfg.ChainID)
	}

	cfg.SetDefaults()
	return &cfg, nil
}

func (c *TOMLConfig) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

func (c *TOMLConfig) SetDefaults() {
	cfg := Defaults()
	cfg.SetFrom(c)
	*c = cfg

	// Set network name defaults
	if c.NetworkName == nil || *c.NetworkName == "" {
		// Check if known network by chain ID
		network, err := GetNetworkConfig(*c.ChainID)
		name := "unknown"
		if err == nil {
			name = network.Name
		}
		c.NetworkName = &name
	}

	// Set network name full defaults
	if c.NetworkNameFull == nil || *c.NetworkNameFull == "" {
		full := ChainFamilyName + "-" + *c.NetworkName
		c.NetworkNameFull = &full
	}
}

func (c *TOMLConfig) ValidateConfig() (err error) {
	if c.ChainID == nil {
		err = errors.Join(err, config.ErrMissing{Name: "ChainID", Msg: "required for all chains"})
	} else if *c.ChainID == "" {
		err = errors.Join(err, config.ErrEmpty{Name: "ChainID", Msg: "required for all chains"})
	}

	// If network name is set, ensure it matches a known network if chain ID is known
	if c.NetworkName != nil && *c.NetworkName != "" {
		var network aptos.NetworkConfig
		network, err = GetNetworkConfig(*c.ChainID)
		if err == nil && *c.NetworkName != network.Name {
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

func (c *TOMLConfig) SetFrom(f *TOMLConfig) {
	if f.Enabled != nil {
		c.Enabled = f.Enabled
	}
	if f.ChainID != nil {
		c.ChainID = f.ChainID
	}

}

func (c *TOMLConfig) GetChainInfo() types.ChainInfo {
	// Construct the chain information from the config
	chainInfo := types.ChainInfo{
		FamilyName: ChainFamilyName, // static for this plugin
	}
	if c.ChainID != nil {
		chainInfo.ChainID = *c.ChainID
	}
	if c.NetworkName != nil {
		chainInfo.NetworkName = *c.NetworkName
	}
	if c.NetworkNameFull != nil {
		chainInfo.NetworkNameFull = *c.NetworkNameFull
	}
	return chainInfo
}

type Nodes []*Node
