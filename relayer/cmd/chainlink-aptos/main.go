package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-plugin"
	"github.com/pelletier/go-toml/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer"
	chain "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/config"
)

const (
	loggerName = "PluginAptos"
)

func main() {
	s := loop.MustNewStartedServer(loggerName)
	defer s.Stop()

	p := &pluginRelayer{Plugin: loop.Plugin{Logger: s.Logger}}
	defer s.Logger.ErrorIfFn(p.Close, "Failed to close")

	s.MustRegister(p)

	stopCh := make(chan struct{})
	defer close(stopCh)

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: loop.PluginRelayerHandshakeConfig(),
		Plugins: map[string]plugin.Plugin{
			loop.PluginRelayerName: &loop.GRPCPluginRelayer{
				PluginServer: p,
				BrokerConfig: loop.BrokerConfig{
					StopCh:   stopCh,
					Logger:   s.Logger,
					GRPCOpts: s.GRPCOpts,
				},
			},
		},
		GRPCServer: s.GRPCOpts.NewServer,
	})
}

type pluginRelayer struct {
	loop.Plugin
}

// NewRelayer implements the Loopp factory method used by the Loopp server to instantiate a aptos relayer
// [github.com/smartcontractkit/chainlink-common/pkg/loop.PluginRelayer]
// loopKs must be an implementation that can construct a aptos keystore adapter
// [github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm.NewKeystoreAdapter]
func (c *pluginRelayer) NewRelayer(ctx context.Context, rawConfig string, loopKs loop.Keystore, capRegistry core.CapabilitiesRegistry) (loop.Relayer, error) {
	d := toml.NewDecoder(strings.NewReader(rawConfig))
	d.DisallowUnknownFields()

	var cfg config.TOMLConfig

	if err := d.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config toml: %w:\n\t%s", err, rawConfig)
	}

	if err := cfg.ValidateConfig(); err != nil {
		return nil, fmt.Errorf("invalid aptos config: %w", err)
	}

	if !cfg.IsEnabled() {
		return nil, fmt.Errorf("cannot create new chain with ID %s: config is disabled", cfg.ChainID)
	}

	cfg.SetDefaults()

	opts := chain.ChainOpts{
		Logger:   c.Logger,
		KeyStore: loopKs,
	}

	chain, err := chain.NewChain(&cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain: %w", err)
	}

	relay, err := relayer.NewRelayer(c.Logger, chain, capRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay: %w", err)
	}

	ra := &loop.RelayerAdapter{Relayer: relay, RelayerExt: chain}

	c.SubService(ra)

	return ra, nil
}
