package chainwriter

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/go-viper/mapstructure/v2"
	"github.com/shopspring/decimal"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	crutils "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/utils"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

type aptosChainWriter struct {
	logger    logger.Logger
	txm       *txm.AptosTxm
	feeClient aptos.AptosRpcClient
	config    ChainWriterConfig

	starter utils.StartStopOnce
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
	return a.starter.StartOnce(a.Name(), func() error {
		return nil
	})
}

func (a *aptosChainWriter) Close() error {
	return a.starter.StopOnce(a.Name(), func() error {
		return nil
	})
}

func convertFunctionParams(argMap map[string]interface{}, params []crconfig.AptosFunctionParam) ([]string, []any, error) {
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
	if value != nil && value.Sign() != 0 {
		return fmt.Errorf("value is not supported")
	}

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

	// temp: extract and set gas limit for CCIP offramp:execute
	meta, err = adjustTxMetaForCCIPExecute(meta, moduleName, functionName, paramValues)
	if err != nil {
		ctxLogger.Errorw("failed to adjust transaction meta for CCIP offramp::execute", "toAddress", toAddress, "error", err)
		return fmt.Errorf("failed to adjust transaction meta for CCIP offramp::execute: %+w", err)
	}

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

	ctxLogger.Infow("submitted transaction for execution", "contractName", contractName, "method", method, "toAddress", toAddress)
	return nil
}

func (a *aptosChainWriter) GetTransactionStatus(ctx context.Context, transactionID string) (commontypes.TransactionStatus, error) {
	return a.txm.GetStatus(transactionID)
}

func (a *aptosChainWriter) GetTransactionFee(ctx context.Context, transactionID string) (decimal.Decimal, error) {
	fee, err := a.txm.GetTransactionFee(ctx, transactionID)
	if err != nil {
		return decimal.Decimal{}, err
	}
	return decimal.NewFromBigInt(fee, -8), nil // Convert from octas (1e-8 APT) to APT
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

func (a *aptosChainWriter) GetEstimateFee(ctx context.Context, contract, method string, args any, toAddress string, meta *commontypes.TxMeta, val *big.Int) (commontypes.EstimateFee, error) {
	return commontypes.EstimateFee{}, errors.New("not implemented")
}

func adjustTxMetaForCCIPExecute(meta *commontypes.TxMeta, moduleName, functionName string, paramValues []any) (*commontypes.TxMeta, error) {
	// Skip non-CCIP offramp:execute tx
	if moduleName != "offramp" || functionName != "execute" {
		return meta, nil
	}

	// Skip gas limit already set
	if meta != nil && meta.GasLimit != nil {
		return meta, nil
	}

	if len(paramValues) < 2 {
		return meta, fmt.Errorf("expected 2 parameters for %s::%s, got %d", moduleName, functionName, len(paramValues))
	}

	reportBytes, ok := paramValues[1].([]byte)
	if !ok {
		return meta, fmt.Errorf("expected report parameter to be []byte, got %T", paramValues[1])
	}

	report, err := crutils.DeserializeExecutionReport(reportBytes)
	if err != nil {
		return meta, fmt.Errorf("failed to deserialize execution report: %+w", err)
	}

	if report == nil {
		return meta, fmt.Errorf("execution report is nil")
	}

	if report.Message.GasLimit == nil {
		return meta, fmt.Errorf("execution report gas limit is nil")
	}

	totalGasLimit := new(big.Int).Set(report.Message.GasLimit)

	for _, tokenAmount := range report.Message.TokenAmounts {
		destGasAmount := new(big.Int).SetUint64(uint64(tokenAmount.DestGasAmount))
		totalGasLimit.Add(totalGasLimit, destGasAmount)
	}

	if meta == nil {
		meta = &commontypes.TxMeta{
			GasLimit: totalGasLimit,
		}
	} else {
		meta.GasLimit = totalGasLimit
	}

	return meta, nil
}
