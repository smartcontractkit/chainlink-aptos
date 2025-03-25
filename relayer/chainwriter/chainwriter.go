package chainwriter

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/mitchellh/mapstructure"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

type aptosChainWriter struct {
	logger    logger.Logger
	txm       *txm.AptosTxm
	feeClient aptos.AptosRpcClient
	config    ChainWriterConfig

	starter utils.StartStopOnce
	stop    chan struct{}
}

func NewChainWriter(lgr logger.Logger, feeClient aptos.AptosRpcClient, txm *txm.AptosTxm, config ChainWriterConfig) commontypes.ContractWriter {
	return &aptosChainWriter{
		logger:    logger.Named(lgr, "AptosChainWriter"),
		txm:       txm,
		feeClient: feeClient,

		// TODO: validate config
		config: config,
	}
}

func (a *aptosChainWriter) Name() string {
	return a.logger.Name()
}

func (a *aptosChainWriter) Ready() error {
	return a.starter.Ready()
}

func (a *aptosChainWriter) HealthReport() map[string]error {
	return map[string]error{a.Name(): a.starter.Healthy()}
}

func (a *aptosChainWriter) Start(ctx context.Context) error {
	return a.starter.StartOnce("aptosChainWriter", func() error {
		return nil
	})
}

func (a *aptosChainWriter) Close() error {
	return a.starter.StopOnce("aptosChainWriter", func() error {
		close(a.stop)
		return nil
	})
}

func convertFunctionParams(argMap map[string]interface{}, params []chainreader.AptosFunctionParam) ([]string, []any, error) {
	types := make([]string, len(params))
	values := make([]any, len(params))

	for i, paramConfig := range params {
		argValue, ok := argMap[paramConfig.Name]
		if !ok {
			if paramConfig.Required {
				return nil, nil, fmt.Errorf("missing argument: %s", paramConfig.Name)
			}
			argValue = paramConfig.DefaultValue
		}

		types[i] = paramConfig.Type
		values[i] = argValue
	}

	return types, values, nil
}

func (a *aptosChainWriter) SubmitTransaction(ctx context.Context, contractName, method string, args any, transactionID string, toAddress string, meta *commontypes.TxMeta, value *big.Int) error {
	moduleConfig, ok := a.config.Modules[contractName]
	if !ok {
		return fmt.Errorf("no such contract: %s", contractName)
	}

	functionConfig, ok := moduleConfig.Functions[method]
	if !ok {
		return fmt.Errorf("no such method: %s", method)
	}

	argMap := make(map[string]interface{})
	err := mapstructure.Decode(args, &argMap)
	if err != nil {
		return fmt.Errorf("failed to parse arguments: %+w", err)
	}

	paramTypes := []string{}
	paramValues := []any{}
	if functionConfig.Params != nil {
		paramTypes, paramValues, err = convertFunctionParams(argMap, functionConfig.Params)
		if err != nil {
			return fmt.Errorf("failed to encode params: %+w", err)
		}
	}

	var moduleName string
	if moduleConfig.Name != "" {
		moduleName = moduleConfig.Name
	} else {
		moduleName = contractName
	}

	var functionName string
	if functionConfig.Name != "" {
		functionName = functionConfig.Name
	} else {
		functionName = method
	}

	ctxLogger := txm.GetContexedTxLogger(a.logger, transactionID, meta)

	err = a.txm.Enqueue(
		transactionID,
		meta,
		functionConfig.FromAddress,
		functionConfig.PublicKey,
		fmt.Sprintf("%s::%s::%s", toAddress, moduleName, functionName),
		/* typeArgs= */ []string{},
		paramTypes,
		paramValues,
		/* simulateTx= */ true,
	)

	if err != nil {
		ctxLogger.Errorw("failed to enqueue transaction", "contractName", contractName, "method", method, "toAddress", toAddress, "error", err)
		return fmt.Errorf("failed to enqueue transaction %s: %+w", transactionID, err)
	}

	ctxLogger.Infow("Workflow DON submitted transaction for execution", "contractName", contractName, "method", method, "toAddress", toAddress)
	return nil
}

func (a *aptosChainWriter) GetTransactionStatus(ctx context.Context, transactionID string) (commontypes.TransactionStatus, error) {
	return a.txm.GetStatus(transactionID)
}

func (a *aptosChainWriter) GetFeeComponents(ctx context.Context) (*commontypes.ChainFeeComponents, error) {
	if a.feeClient == nil {
		return nil, errors.New("fee estimation not available")
	}

	estimation, err := a.feeClient.EstimateGasPrice()
	if err != nil {
		return nil, fmt.Errorf("failed to estimate gas price: %+w", err)
	}

	var fee uint64
	switch a.config.FeeStrategy {
	case DeprioritizedFeeStrategy:
		fee = estimation.DeprioritizedGasEstimate
	case PrioritizedFeeStrategy:
		fee = estimation.PrioritizedGasEstimate
	case DefaultFeeStrategy:
		fee = estimation.GasEstimate
	default:
		return nil, fmt.Errorf("invalid fee strategy: %d", a.config.FeeStrategy)
	}

	return &commontypes.ChainFeeComponents{
		ExecutionFee:        new(big.Int).SetUint64(fee),
		DataAvailabilityFee: big.NewInt(0),
	}, nil
}
