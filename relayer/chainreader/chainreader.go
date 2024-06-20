package chainreader

import (
	"context"
	"errors"

	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

type aptosChainReader struct {
	logger  logger.Logger
	rpcUrl  string
	client  *aptos.NodeClient
	starter utils.StartStopOnce
}

func NewChainReader(lgr logger.Logger, rpcUrl string, config ChainReaderConfig) types.ContractReader {
	return &aptosChainReader{
		logger: logger.Named(lgr, "AptosChainReader"),
	}
}

func (a *aptosChainReader) Name() string {
	return a.logger.Name()
}

func (a *aptosChainReader) Ready() error {
	return a.starter.Ready()
}

func (a *aptosChainReader) HealthReport() map[string]error {
	return map[string]error{a.Name(): a.starter.Healthy()}
}

func (a *aptosChainReader) GetClient() (*aptos.NodeClient, error) {
	if a.client == nil {
		client, err := aptos.NewNodeClient(a.rpcUrl, 0)
		if err != nil {
			return nil, err
		}
		a.client = client
	}
	return a.client, nil
}

func (a *aptosChainReader) Start(ctx context.Context) error {
	return a.starter.StartOnce("AptosChainReader", func() error {
		return nil
	})
}

func (a *aptosChainReader) Close() error {
	return a.starter.StopOnce("AptosChainReader", func() error {
		return nil
	})
}

func (a *aptosChainReader) GetLatestValue(ctx context.Context, contractName, method string, params, returnVal any) error {
	return errors.New("TODO")
}

func (a *aptosChainReader) Bind(ctx context.Context, bindings []types.BoundContract) error {
	return errors.New("TODO")
}

func (a *aptosChainReader) QueryKey(ctx context.Context, contractName string, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]types.Sequence, error) {
	return nil, errors.New("TODO")
}
