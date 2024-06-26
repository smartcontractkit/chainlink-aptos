package relayer

import (
	"context"
	"errors"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	relaytypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	chain "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/write_target"
)

var _ relaytypes.Relayer = (*relayer)(nil) //nolint:staticcheck

type relayer struct {
	chain  chain.Chain
	stopCh services.StopChan

	lggr logger.Logger
}

func NewRelayer(lggr logger.Logger, chain chain.Chain, capRegistry core.CapabilitiesRegistry) (*relayer, error) {
	ctx := context.TODO()

	cap, err := write_target.NewAptosWriteTarget(ctx, chain, lggr)
	if err != nil {
		return nil, err
	}
	if err = capRegistry.Add(ctx, cap); err != nil {
		return nil, err
	}

	return &relayer{
		chain:  chain,
		stopCh: make(chan struct{}),
		lggr:   lggr,
	}, nil
}

func (r *relayer) Name() string {
	return r.lggr.Name()
}

func (r *relayer) Start(context.Context) error {
	return nil
}

func (r *relayer) Close() error {
	close(r.stopCh)
	return nil
}

func (r *relayer) Ready() error {
	return r.chain.Ready()
}

func (r *relayer) Healthy() error { return nil }

func (r *relayer) HealthReport() map[string]error {
	return map[string]error{r.Name(): r.Healthy()}
}

func (r *relayer) NewContractReader(_ []byte) (relaytypes.ContractReader, error) {
	return nil, errors.New("contract reader is not supported for aptos")
}

func (r *relayer) NewConfigProvider(args relaytypes.RelayArgs) (relaytypes.ConfigProvider, error) {
	return nil, errors.New("ocr2 is not supported for aptos")
}

func (r *relayer) NewMedianProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.MedianProvider, error) {
	return nil, errors.New("ocr2 is not supported for aptos")
}

func (r *relayer) NewMercuryProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.MercuryProvider, error) {
	return nil, errors.New("mercury is not supported for aptos")
}

func (r *relayer) NewLLOProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.LLOProvider, error) {
	return nil, errors.New("data streams is not supported for aptos")
}

func (r *relayer) NewFunctionsProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.FunctionsProvider, error) {
	return nil, errors.New("functions are not supported for aptos")
}

func (r *relayer) NewAutomationProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.AutomationProvider, error) {
	return nil, errors.New("automation is not supported for aptos")
}

func (r *relayer) NewPluginProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.PluginProvider, error) {
	return nil, errors.New("plugin provider is not supported for aptos")
}

func (r *relayer) NewOCR3CapabilityProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.OCR3CapabilityProvider, error) {
	return nil, errors.New("ocr3 capability provider is not supported for aptos")
}

func (r *relayer) NewCCIPCommitProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.CCIPCommitProvider, error) {
	return nil, errors.New("ccip.commit is not supported for aptos")
}

func (r *relayer) NewCCIPExecProvider(rargs relaytypes.RelayArgs, pargs relaytypes.PluginArgs) (relaytypes.CCIPExecProvider, error) {
	return nil, errors.New("ccip.exec is not supported for aptos")
}
