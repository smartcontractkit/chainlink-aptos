package relayer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainwriter"
	write_target "github.com/smartcontractkit/chainlink-aptos/relayer/write_target/aptos"
)

var _ types.AptosService = (*relayer)(nil)
var _ loop.Relayer = (*relayer)(nil)

type relayer struct {
	chain chain.Chain
	lggr  logger.Logger

	starter utils.StartStopOnce
	stopCh  services.StopChan
	aptosService
}

func NewRelayer(lggr logger.Logger, chain chain.Chain, capRegistry core.CapabilitiesRegistry) (*relayer, error) {
	ctx := context.TODO()

	// TODO: Deprecate this after CRE migration is complete
	if chain.Config().Workflow != nil {
		capability, err := write_target.NewAptosWriteTarget(ctx, chain, lggr)
		if err != nil {
			return nil, err
		}
		if err = capRegistry.Add(ctx, capability); err != nil {
			return nil, err
		}
	} else {
		lggr.Warn("No workflow config found, skipping write target creation")
	}

	return &relayer{
		chain:  chain,
		lggr:   lggr,
		stopCh: make(chan struct{}),
		aptosService: aptosService{
			chain:  chain,
			logger: lggr,
		},
	}, nil
}

func (r *relayer) Name() string {
	return r.lggr.Name()
}

func (r *relayer) Replay(ctx context.Context, fromBlock string, args map[string]any) error {
	return errors.ErrUnsupported
}

// Start starts the relayer respecting the given context.
func (r *relayer) Start(ctx context.Context) error {
	return r.starter.StartOnce("AptosRelayer", func() error {
		r.lggr.Debug("Starting")
		r.lggr.Debug("Starting chain")

		if r.chain == nil {
			return errors.New("Aptos unavailable")
		}

		var ms services.MultiStart
		return ms.Start(ctx, r.chain)
	})
}

// Close will close all open subservices
func (r *relayer) Close() error {
	return r.starter.StopOnce("AptosRelayer", func() error {
		r.lggr.Debug("Stopping")
		r.lggr.Debug("Stopping chain")

		close(r.stopCh)
		return services.CloseAll(r.chain)
	})
}

func (r *relayer) Ready() error {
	return r.chain.Ready()
}

func (r *relayer) Healthy() error { return nil }

func (r *relayer) HealthReport() map[string]error {
	return map[string]error{r.Name(): r.Healthy()}
}

func (r *relayer) NewContractWriter(ctx context.Context, configBytes []byte) (types.ContractWriter, error) {
	cfg := chainwriter.ChainWriterConfig{}
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshall chain writer config err: %s", err)
	}

	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	chainWriter := chainwriter.NewChainWriter(r.lggr, client, r.chain.TxManager(), cfg)
	return chainWriter, nil
}

func (r *relayer) NewContractReader(ctx context.Context, configBytes []byte) (types.ContractReader, error) {
	cfg := crconfig.ChainReaderConfig{}
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshall chain reader config err: %s", err)
	}

	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	chainReader := chainreader.NewChainReader(r.lggr, client, cfg, r.chain.DataSource(), r.chain.LogPoller())
	return chainReader, nil
}

func (r *relayer) NewConfigProvider(ctx context.Context, args types.RelayArgs) (types.ConfigProvider, error) {
	return nil, errors.New("ocr2 is not supported for aptos")
}

func (r *relayer) NewPluginProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.PluginProvider, error) {
	return nil, errors.New("plugin provider is not supported for aptos")
}

func (r *relayer) NewLLOProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.LLOProvider, error) {
	return nil, errors.New("data streams is not supported for aptos")
}

func (r *relayer) NewCCIPProvider(ctx context.Context, cargs types.CCIPProviderArgs) (types.CCIPProvider, error) {
	_ = ctx
	_ = cargs
	return nil, errors.New("ccip provider is not supported for aptos")
}

func (r *relayer) EVM() (types.EVMService, error) {
	return nil, errors.New("EVMService is not supported for aptos")
}

func (r *relayer) TON() (types.TONService, error) {
	return nil, errors.New("TONService is not supported for aptos")
}

func (r *relayer) Solana() (types.SolanaService, error) {
	return nil, errors.New("SolanaService is not supported for aptos")
}

func (r *relayer) Aptos() (types.AptosService, error) {
	return r, nil
}

// ChainService interface
func (r *relayer) GetChainStatus(ctx context.Context) (types.ChainStatus, error) {
	return r.chain.GetChainStatus(ctx)
}

func (r *relayer) LatestHead(ctx context.Context) (types.Head, error) {
	return r.chain.LatestHead(ctx)
}

func (r *relayer) FinalizedHead(ctx context.Context) (types.Head, error) {
	return r.chain.FinalizedHead(ctx)
}

func (r *relayer) GetChainInfo(ctx context.Context) (types.ChainInfo, error) {
	return r.chain.GetChainInfo(ctx)
}

func (r *relayer) ListNodeStatuses(ctx context.Context, pageSize int32, pageToken string) (stats []types.NodeStatus, nextPageToken string, total int, err error) {
	return r.chain.ListNodeStatuses(ctx, pageSize, pageToken)
}

func (r *relayer) Transact(ctx context.Context, from, to string, amount *big.Int, balanceCheck bool) error {
	return r.chain.Transact(ctx, from, to, amount, balanceCheck)
}
