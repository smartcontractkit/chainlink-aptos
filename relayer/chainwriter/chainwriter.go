package chainwriter

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/mitchellh/mapstructure"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

type aptosChainWriter struct {
	logger logger.Logger
	txm    *txm.AptosTxm
	config ChainWriterConfig

	starter utils.StartStopOnce
	done    sync.WaitGroup
	stop    chan struct{}
}

func NewChainWriter(lgr logger.Logger, txm *txm.AptosTxm, config ChainWriterConfig) commontypes.ChainWriter {
	return &aptosChainWriter{
		logger: logger.Named(lgr, "AptosChainWriter"),
		txm:    txm,
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
		a.done.Wait()
		return nil
	})
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
	if err := mapstructure.Decode(args, &argMap); err != nil {
		return fmt.Errorf("failed to parse arguments: %+w", err)
	}

	paramTypes := []string{}
	paramValues := []any{}

	if functionConfig.Params != nil {
		for _, paramConfig := range functionConfig.Params {
			argValue, ok := argMap[paramConfig.Name]
			if !ok {
				if paramConfig.Required {
					return fmt.Errorf("missing argument: %s", paramConfig.Name)
				}
				argValue = paramConfig.DefaultValue
			}

			paramTypes = append(paramTypes, paramConfig.Type)
			paramValues = append(paramValues, argValue)
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

	err := a.txm.Enqueue(
		transactionID,
		functionConfig.FromAddress,
		functionConfig.PublicKey,
		fmt.Sprintf("%s::%s::%s", toAddress, moduleName, functionName),
		/* typeArgs= */ []string{},
		paramTypes,
		paramValues)

	if err != nil {
		a.logger.Errorw("failed to enqueue transaction", "transactionID", transactionID, "contractName", contractName, "method", method, "toAddress", toAddress, "error", err)
		return fmt.Errorf("failed to enqueue transaction %s: %+w", transactionID, err)
	}

	a.logger.Infow("submitted transaction", "transactionID", transactionID, "contractName", contractName, "method", method, "toAddress", toAddress)
	return nil
}

func (a *aptosChainWriter) GetTransactionStatus(ctx context.Context, transactionID string) (commontypes.TransactionStatus, error) {
	return a.txm.GetStatus(transactionID)
}

func (a *aptosChainWriter) GetFeeComponents(ctx context.Context) (*commontypes.ChainFeeComponents, error) {
	return nil, errors.New("not implemented")
}
