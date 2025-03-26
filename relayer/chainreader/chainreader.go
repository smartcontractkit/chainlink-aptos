package chainreader

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/mitchellh/mapstructure"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

type aptosChainReader struct {
	types.UnimplementedContractReader

	logger                logger.Logger
	config                ChainReaderConfig
	starter               utils.StartStopOnce
	moduleAddresses       map[string]aptos.AccountAddress
	eventAccountAddresses map[string]aptos.AccountAddress

	client aptos.AptosRpcClient
}

func NewChainReader(lgr logger.Logger, client aptos.AptosRpcClient, config ChainReaderConfig) types.ContractReader {
	return &aptosChainReader{
		logger:                logger.Named(lgr, "AptosChainReader"),
		client:                client,
		config:                config,
		moduleAddresses:       map[string]aptos.AccountAddress{},
		eventAccountAddresses: map[string]aptos.AccountAddress{},
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
	// TODO: check chainlink-solana/pkg/solana/chainreader/lookup.go, see if we can use the same approach
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

	return codec.DecodeAptosAPIResponse(data, returnVal)
}

func (a *aptosChainReader) BatchGetLatestValues(ctx context.Context, request types.BatchGetLatestValuesRequest) (types.BatchGetLatestValuesResult, error) {
	result := make(types.BatchGetLatestValuesResult)

	for contract, batch := range request {
		batchResults := make(types.ContractBatchResults, len(batch))
		resultChan := make(chan struct {
			index  int
			result types.BatchReadResult
		}, len(batch))

		for i, read := range batch {
			go func(index int, read types.BatchRead) {
				readResult := types.BatchReadResult{ReadName: read.ReadName}

				err := a.GetLatestValue(ctx, contract.ReadIdentifier(read.ReadName), primitives.Finalized, read.Params, read.ReturnVal)
				readResult.SetResult(read.ReturnVal, err)

				select {
				case resultChan <- struct {
					index  int
					result types.BatchReadResult
				}{index, readResult}:
				case <-ctx.Done():
					return
				}
			}(i, read)
		}

		for range batch {
			select {
			case res := <-resultChan:
				batchResults[res.index] = res.result
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		result[contract] = batchResults
	}

	return result, nil
}

func (a *aptosChainReader) QueryKey(ctx context.Context, contract types.BoundContract, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]types.Sequence, error) {
	contractName := contract.Name

	address, ok := a.moduleAddresses[contractName]
	if !ok {
		return nil, fmt.Errorf("no bound address for module %s", contractName)
	}

	if address.String() != contract.Address {
		return nil, fmt.Errorf("bound address %s for module %s does not match provided address %s", address, contractName, contract.Address)
	}

	eventKey := filter.Key
	// temp: parsing offset from queryFilter because limitAndSort doesn't support offset-based pagination
	var eventOffset uint64 = 0
	for _, expr := range filter.Expressions {
		if expr.IsPrimitive() {
			if comparator, ok := expr.Primitive.(*primitives.Comparator); ok && comparator.Name == "offset" {
				for _, valueComparator := range comparator.ValueComparators {
					if valueComparator.Operator == primitives.Eq {
						if value, ok := valueComparator.Value.(uint64); ok {
							eventOffset = value
						} else {
							return nil, fmt.Errorf("offset value is not an integer: %v", valueComparator.Value)
						}
					}
				}
			}
		}
	}

	limit := limitAndSort.Limit.Count

	moduleConfig, ok := a.config.Modules[contractName]
	if !ok {
		return nil, fmt.Errorf("no such module: %s", contractName)
	}

	eventConfig, ok := moduleConfig.Events[eventKey]
	if !ok {
		return nil, fmt.Errorf("no such event key: %s", eventKey)
	}

	var eventModuleName string
	var eventAccountAddress aptos.AccountAddress

	if moduleConfig.Name != "" {
		eventModuleName = moduleConfig.Name
	} else {
		eventModuleName = contractName
	}

	if len(eventConfig.EventAccountAddress) == 0 {
		eventAccountAddress = address
	} else {
		components := strings.Split(eventConfig.EventAccountAddress, "::")

		if len(components) == 1 {
			err := eventAccountAddress.ParseStringRelaxed(components[0])
			if err != nil {
				return nil, fmt.Errorf("failed to parse event account address: %+w", err)
			}
		} else {
			var addressFunctionAddress aptos.AccountAddress
			var addressFunctionModuleName string
			var addressFunctionFunctionName string
			if len(components) == 3 {
				err := addressFunctionAddress.ParseStringRelaxed(components[0])
				if err != nil {
					return nil, fmt.Errorf("failed to parse event account address function address: %+w", err)
				}
				addressFunctionModuleName = components[1]
				addressFunctionFunctionName = components[2]
			} else if len(components) == 2 {
				addressFunctionAddress = address
				addressFunctionModuleName = components[0]
				addressFunctionFunctionName = components[1]
			} else {
				return nil, fmt.Errorf("invalid event account address definition: %s", eventConfig.EventAccountAddress)
			}

			cacheKey := addressFunctionAddress.String() + "::" + addressFunctionModuleName + "::" + addressFunctionFunctionName
			if cachedAddress, ok := a.eventAccountAddresses[cacheKey]; ok {
				eventAccountAddress = cachedAddress
			} else {
				viewPayload := &aptos.ViewPayload{
					Module: aptos.ModuleId{
						Address: addressFunctionAddress,
						Name:    addressFunctionModuleName,
					},
					Function: addressFunctionFunctionName,
					ArgTypes: []aptos.TypeTag{},
					Args:     [][]byte{},
				}

				data, err := a.client.View(viewPayload)
				if err != nil {
					return nil, fmt.Errorf("failed to call view function: %+w", err)
				}

				err = codec.DecodeAptosAPIResponse(data, &eventAccountAddress)
				if err != nil {
					return nil, fmt.Errorf("failed to decode event account address function output: %+w", err)
				}
				a.eventAccountAddresses[cacheKey] = eventAccountAddress
			}
		}
	}

	eventHandle := address.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName

	events, err := a.client.EventsByHandle(eventAccountAddress, eventHandle, eventConfig.EventHandleFieldName, &eventOffset, &limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %+w", err)
	}

	for _, sortBy := range limitAndSort.SortBy {
		if seqSort, ok := sortBy.(query.SortBySequence); ok {
			sort.Slice(events, func(i, j int) bool {
				if seqSort.GetDirection() == query.Desc {
					return events[i].SequenceNumber > events[j].SequenceNumber
				}
				return events[i].SequenceNumber < events[j].SequenceNumber
			})
		}
	}

	var sequences []types.Sequence
	for _, event := range events {
		jsonData := event.Data

		if err := renameFields(jsonData, eventConfig.EventFieldRenames); err != nil {
			return nil, fmt.Errorf("failed to rename event fields: %+w", err)
		}

		// create new instance of eventData for each event
		eventData := reflect.New(reflect.TypeOf(sequenceDataType).Elem()).Interface()

		err := codec.DecodeAptosJsonValue(jsonData, &eventData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode event data: %+w", err)
		}

		sequence := types.Sequence{
			Cursor: fmt.Sprintf("%d", event.SequenceNumber),
			// todo: enrich with block data?
			Head: types.Head{},
			Data: eventData,
		}
		sequences = append(sequences, sequence)
	}

	return sequences, nil
}

func renameFields(jsonData map[string]any, renames map[string]RenamedEventField) error {
	if renames == nil {
		return nil
	}
	for origName, rename := range renames {
		jsonValue, ok := jsonData[origName]
		if !ok {
			return fmt.Errorf("no such field: %s", origName)
		}
		jsonData[rename.NewName] = jsonValue
		delete(jsonData, origName)

		if jsonMap, ok := jsonValue.(map[string]any); ok {
			if err := renameFields(jsonMap, rename.SubFieldRenames); err != nil {
				return err
			}
		} else if jsonSlice, ok := jsonValue.([]any); ok {
			for i, elem := range jsonSlice {
				if elemMap, ok := elem.(map[string]any); ok {
					if err := renameFields(elemMap, rename.SubFieldRenames); err != nil {
						return err
					}
				} else {
					if len(rename.SubFieldRenames) > 0 {
						return fmt.Errorf("sub field renames provided for field '%s' but array element at index %d is not a map", origName, i)
					}
				}
			}
		} else {
			if len(rename.SubFieldRenames) > 0 {
				return fmt.Errorf("sub field renames provided for field '%s' but value is not a map", origName)
			}
		}
	}
	return nil
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
