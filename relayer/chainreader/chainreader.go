package chainreader

import (
	"context"
	"errors"
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/mitchellh/mapstructure"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

type aptosChainReader struct {
	logger          logger.Logger
	config          ChainReaderConfig
	starter         utils.StartStopOnce
	moduleAddresses map[string]aptos.AccountAddress

	client *aptos.NodeClient
}

func NewChainReader(lgr logger.Logger, config ChainReaderConfig, client *aptos.NodeClient) types.ContractReader {
	return &aptosChainReader{
		logger:          logger.Named(lgr, "AptosChainReader"),
		client:          client,
		config:          config,
		moduleAddresses: map[string]aptos.AccountAddress{},
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
	toAddress, ok := a.moduleAddresses[contractName]
	if !ok {
		return fmt.Errorf("no bound address for module %s", contractName)
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
	if err := mapstructure.Decode(params, &argMap); err != nil {
		return fmt.Errorf("failed to parse arguments: %+w", err)
	}

	paramValues := [][]byte{}

	if functionConfig.Params != nil {
		for _, paramConfig := range functionConfig.Params {
			argValue, ok := argMap[paramConfig.Name]
			if !ok {
				if paramConfig.Required {
					return fmt.Errorf("missing argument: %s", paramConfig.Name)
				}
				argValue = paramConfig.DefaultValue
			}

			typeTag, err := txm.CreateTypeTag(paramConfig.Type)
			if err != nil {
				return fmt.Errorf("failed to parse type %s: %+w", paramConfig.Type, err)
			}

			bcsValue, err := txm.CreateBcsValue(typeTag, argValue)
			if err != nil {
				return fmt.Errorf("failed to serialize value %s: %+w", argValue, err)
			}

			paramValues = append(paramValues, bcsValue)
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

	viewPayload := &aptos.ViewPayload{
		Module: aptos.ModuleId{
			Address: toAddress,
			Name:    moduleName,
		},
		Function: functionName,
		ArgTypes: []aptos.TypeTag{},
		Args:     paramValues,
	}

	data, err := a.client.View(viewPayload)
	if err != nil {
		return fmt.Errorf("failed to call view function: %+w", err)
	}

	return decodeAptosJsonValue(data, returnVal)
}

func (a *aptosChainReader) Bind(ctx context.Context, bindings []types.BoundContract) error {
	newBindings := map[string]aptos.AccountAddress{}
	for _, binding := range bindings {
		moduleAddress := &aptos.AccountAddress{}
		err := moduleAddress.ParseStringRelaxed(binding.Address)
		if err != nil {
			return fmt.Errorf("failed to convert module address %s: %+w", binding.Address, err)
		}
		newBindings[binding.Name] = *moduleAddress
	}

	for name, address := range newBindings {
		a.moduleAddresses[name] = address
	}

	return nil
}

func (a *aptosChainReader) QueryKey(ctx context.Context, contractName string, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]types.Sequence, error) {
	return nil, errors.New("not implemented")
}
