package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-plugin"

	"github.com/smartcontractkit/chainlink-common/pkg/beholder"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-aptos/relayer"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/config"
)

const (
	loggerName = "PluginAptos"
)

func main() {
	s := loop.MustNewStartedServer(loggerName)
	defer s.Stop()

	p := &pluginRelayer{Plugin: loop.Plugin{Logger: s.Logger}, ds: s.DataSource}
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
	ds sqlutil.DataSource
}

// NewRelayer implements the Loopp factory method used by the Loopp server to instantiate an aptos relayer.
// [github.com/smartcontractkit/chainlink-common/pkg/loop.PluginRelayer]
// loopKs must be an implementation that can construct a aptos keystore adapter
// [github.com/smartcontractkit/chainlink-aptos/relayer/txm.NewKeystoreAdapter]
func (p *pluginRelayer) NewRelayer(ctx context.Context, rawConfig string, loopKs core.Keystore, csaKs core.Keystore, capRegistry core.CapabilitiesRegistry) (loop.Relayer, error) {
	_ = csaKs

	// Initialize the chain service
	cfg, err := config.NewDecodedTOMLConfig(rawConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to read configs: %w", err)
	}

	rawNodes := make([]map[string]string, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n == nil || n.URL == nil {
			continue
		}
		rawNodes = append(rawNodes, map[string]string{"URL": n.URL.String()})
	}
	emitter := loop.NewPluginRelayerConfigEmitter(
		p.Logger,
		beholder.GetClient().Config.AuthPublicKeyHex,
		cfg.ChainID,
		rawNodes,
	)
	if err := emitter.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start plugin relayer config emitter: %w", err)
	}
	p.SubService(emitter)
	opts := chain.ChainOpts{
		Logger:   p.Logger,
		KeyStore: loopKs,
		DS:       p.ds,
	}
	chain, err := chain.NewChain(cfg, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create chain: %w", err)
	}

	// Initialize the relayer service
	relay, err := relayer.NewRelayer(p.Logger, chain, capRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay: %w", err)
	}
	p.SubService(relay)

	return relay, nil
}
