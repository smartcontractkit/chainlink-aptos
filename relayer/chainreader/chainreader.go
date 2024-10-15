package chainreader

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/mitchellh/mapstructure"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/txm"
)

type aptosChainReader struct {
	types.UnimplementedContractReader

	logger          logger.Logger
	config          ChainReaderConfig
	starter         utils.StartStopOnce
	moduleAddresses map[string]aptos.AccountAddress

	client *aptos.NodeClient
}

func NewChainReader(lgr logger.Logger, client *aptos.NodeClient, config ChainReaderConfig) types.ContractReader {
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
	return a.starter.StartOnce(a.Name(), func() error {
		return nil
	})
}

func (a *aptosChainReader) Close() error {
	return a.starter.StopOnce(a.Name(), func() error {
		return nil
	})
}

func (a *aptosChainReader) GetLatestValue(ctx context.Context, readIdentifier string, confidenceLevel primitives.ConfidenceLevel, params, returnVal any) error {
	// Decode the readIdentifier - a combination of address, contract, and readName as a concatenated string
	// TODO: check /chainlink-internal-integrations/solana/pkg/solana/chainreader/lookup.go, see if we can use the same approach
	readComponents := strings.Split(readIdentifier, "-")
	if len(readComponents) != 3 {
		return fmt.Errorf("invalid read identifier: %s", readIdentifier)
	}
	// TODO: rename 'method' as 'readName' (entity name to read) vs. method (function name to call), as defined by CR API spec
	_address, contractName, method := readComponents[0], readComponents[1], readComponents[2]

	// Source the read configuration, by contract name
	address, ok := a.moduleAddresses[contractName]
	if !ok {
		return fmt.Errorf("no bound address for module %s", contractName)
	}

	// Notice: the address in the readIdentifier should match the bound address, by contract name
	if address.String() != _address {
		return fmt.Errorf("bound address %s for module %s does not match read address %s", address, contractName, _address)
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
			Address: address,
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

	return codec.DecodeAptosJsonValue(data, returnVal)
}

func (a *aptosChainReader) BatchGetLatestValues(ctx context.Context, request types.BatchGetLatestValuesRequest) (types.BatchGetLatestValuesResult, error) {
	return nil, errors.New("not implemented")
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

func (a *aptosChainReader) Unbind(ctx context.Context, bindings []types.BoundContract) error {
	for _, binding := range bindings {
		key := binding.Name
		if _, ok := a.moduleAddresses[key]; ok {
			delete(a.moduleAddresses, key)
		} else {
			return fmt.Errorf("no such binding: %s", key)
		}
	}
	return nil
}

func (a *aptosChainReader) QueryKey(ctx context.Context, contract types.BoundContract, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]types.Sequence, error) {
	return nil, errors.ErrUnsupported
}
