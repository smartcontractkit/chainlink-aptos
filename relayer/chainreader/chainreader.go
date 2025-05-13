package chainreader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/go-viper/mapstructure/v2"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/loop"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

type aptosChainReader struct {
	types.UnimplementedContractReader

	logger  logger.Logger
	config  ChainReaderConfig
	dbStore *DBStore
	starter commonutils.StartStopOnce

	moduleAddresses       map[string]aptos.AccountAddress
	eventAccountAddresses map[string]aptos.AccountAddress

	client aptos.AptosRpcClient
}

var _ types.ContractTypeProvider = &aptosChainReader{}

type ExtendedContractReader interface {
	types.ContractReader
	QueryKeyWithMetadata(ctx context.Context, contract types.BoundContract, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]SequenceWithMetadata, error)
}

func NewChainReader(lgr logger.Logger, client aptos.AptosRpcClient, config ChainReaderConfig, ds sqlutil.DataSource) types.ContractReader {
	reader := &aptosChainReader{
		logger:                logger.Named(lgr, "AptosChainReader"),
		client:                client,
		config:                config,
		moduleAddresses:       map[string]aptos.AccountAddress{},
		eventAccountAddresses: map[string]aptos.AccountAddress{},
	}

	if ds != nil {
		reader.dbStore = NewDBStore(ds)
	}

	return reader
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

func (a *aptosChainReader) syncEvent(ctx context.Context, boundAddress aptos.AccountAddress, eventConfig *ChainReaderEvent, eventModuleName string) error {
	if err := a.dbStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("syncEvent: failed to ensure schema: %w", err)
	}

	eventAccountAddress, err := a.computeEventAccountAddress(boundAddress, eventConfig)
	if err != nil {
		return fmt.Errorf("syncEvent: %w", err)
	}

	eventHandle := boundAddress.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName
	latestOffset, err := a.dbStore.GetLatestOffset(ctx, eventAccountAddress.String(), eventHandle)
	if err != nil {
		return fmt.Errorf("syncEvent: failed to get latest offset: %w", err)
	}

	var batchSize uint64 = 25
	var records []EventRecord
	for {
		newEvents, err := a.client.EventsByHandle(eventAccountAddress, eventHandle, eventConfig.EventHandleFieldName, &latestOffset, &batchSize)
		if err != nil {
			a.logger.Errorw("syncEvent: failed to fetch new events", "error", err)
			// If fetching fails, we continue with what is already in the DB
			// todo: should we rather error out?
			break
		}

		if len(newEvents) == 0 {
			break
		}

		for _, event := range newEvents {
			head, err := a.getBlockHead(event.Version)
			if err != nil {
				a.logger.Errorw("syncEvent: failed to fetch block metadata", "version", event.Version, "error", err)
				continue
			}

			if err := renameMapFields(event.Data, eventConfig.EventFieldRenames); err != nil {
				a.logger.Errorw("syncEvent: failed to rename event fields", "error", err)
				continue
			}

			record := EventRecord{
				EventAccountAddress: eventAccountAddress.String(),
				EventHandle:         eventHandle,
				EventOffset:         &event.SequenceNumber,
				TxVersion:           event.Version,
				BlockHeight:         head.Height,
				BlockHash:           head.Hash,
				BlockTimestamp:      head.Timestamp,
				Data:                event.Data,
			}
			records = append(records, record)
		}

		latestOffset = newEvents[len(newEvents)-1].SequenceNumber + 1
	}

	if len(records) > 0 {
		if err := a.dbStore.InsertEvents(ctx, records); err != nil {
			return fmt.Errorf("syncEvent: failed to insert new events: %w", err)
		}
	}

	return nil
}

func (a *aptosChainReader) InitEvents(ctx context.Context) error {
	for moduleKey, moduleConfig := range a.config.Modules {
		if moduleConfig.Events == nil {
			continue
		}

		boundAddress, ok := a.moduleAddresses[moduleKey]
		if !ok {
			a.logger.Warnw("InitEvents: no bound address for module", "module", moduleKey)
			continue
		}

		var eventModuleName string
		if moduleConfig.Name != "" {
			eventModuleName = moduleConfig.Name
		} else {
			eventModuleName = moduleKey
		}

		for eventKey, eventConfig := range moduleConfig.Events {
			if err := a.syncEvent(ctx, boundAddress, eventConfig, eventModuleName); err != nil {
				return fmt.Errorf("InitEvents: module %s event %s: %w", moduleKey, eventKey, err)
			}
		}
	}

	return nil
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

	if moduleConfig.Functions == nil {
		return fmt.Errorf("no functions for contract: %s", contractName)
	}

	functionConfig, ok := moduleConfig.Functions[method]
	if !ok {
		return fmt.Errorf("no such method: %s", method)
	}

	argMap := make(map[string]interface{})

	if a.config.IsLoopPlugin {
		paramBytes := params.(*[]byte)

		// use json.Number to decode uint64 correctly. when we serialize into bcs, serializeArg will convert it into the appropriate number type.
		decoder := json.NewDecoder(bytes.NewReader(*paramBytes))
		decoder.UseNumber()

		err := decoder.Decode(&argMap)
		if err != nil {
			return fmt.Errorf("failed to unmarshal JSON params: %+w", err)
		}
	} else {
		if err := mapstructure.Decode(params, &argMap); err != nil {
			return fmt.Errorf("failed to parse arguments: %+w", err)
		}
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
				return fmt.Errorf("failed to serialize value %+v (type %T) using type tag %s: %+w", argValue, argValue, typeTag.String(), err)
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

	if err := maybeRenameFields(data, functionConfig.ResultFieldRenames); err != nil {
		return fmt.Errorf("failed to rename function return value fields: %+w", err)
	}

	var transformedData any
	if len(functionConfig.ResultTupleToStruct) > 0 {
		if len(data) != len(functionConfig.ResultTupleToStruct) {
			return fmt.Errorf("result wrap mismatch: expected %d elements, got %d", len(functionConfig.ResultTupleToStruct), len(data))
		}
		wrappedResult := make(map[string]any)
		for i, fieldName := range functionConfig.ResultTupleToStruct {
			wrappedResult[fieldName] = data[i]
		}
		transformedData = wrappedResult
	} else {
		// In order to support multi-returns, all values are returned as []any
		// However, vector or tuple return types are not necessary wrapped
		// in an additional slice, eg:
		//   u32 return type -> [1]
		//   (u32, u64) tuple return type -> [1, 2]
		//   vector<u8> return type -> ["0x12345678"]
		//   vector<vector<u8>> return type -> ["0x1234", "0x5678"]
		if len(data) == 1 {
			transformedData = data[0]
		} else {
			transformedData = data
		}
	}

	if len(functionConfig.ResultUnwrapStruct) > 0 {
		unwrapped := transformedData
		for _, key := range functionConfig.ResultUnwrapStruct {
			m, ok := unwrapped.(map[string]any)
			if !ok {
				return fmt.Errorf("result unwrap error: expecting a map at key %s but got %T", key, unwrapped)
			}
			val, exists := m[key]
			if !exists {
				return fmt.Errorf("result unwrap error: key %s not found", key)
			}
			unwrapped = val
		}
		transformedData = unwrapped
	}

	if a.config.IsLoopPlugin {
		// immediately remarshal the data
		// TODO: update aptos-go-sdk to allow returning the string directly
		resultBytes, err := json.Marshal(transformedData)
		if err != nil {
			return fmt.Errorf("failed to re-marshal data: %+w", err)
		}
		returnValPtr, ok := returnVal.(*[]byte)
		if !ok {
			return fmt.Errorf("return value is not a pointer to []byte as expected when running as a LOOP plugin")
		}
		*returnValPtr = make([]byte, len(resultBytes))
		copy(*returnValPtr, resultBytes)
		return nil
	}

	return codec.DecodeAptosJsonValue(transformedData, returnVal)
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
	if a.dbStore == nil {
		return nil, fmt.Errorf("QueryKey only operates in persistent mode")
	}

	contractName := contract.Name
	address, ok := a.moduleAddresses[contractName]

	if !ok {
		return nil, fmt.Errorf("no bound address for module %s", contractName)
	}

	if address.String() != contract.Address {
		return nil, fmt.Errorf("bound address %s for module %s does not match provided address %s", address, contractName, contract.Address)
	}

	var expressions []query.Expression
	if !a.config.IsLoopPlugin {
		expressions = filter.Expressions
	} else {
		convertedExpressions, err := loop.DeserializeExpressions(filter.Expressions)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize QueryKey expressions: %w", err)
		}
		expressions = convertedExpressions
	}

	moduleConfig, ok := a.config.Modules[contractName]
	if !ok {
		return nil, fmt.Errorf("no such module: %s", contractName)
	}

	if moduleConfig.Events == nil {
		return nil, fmt.Errorf("no events for contract: %s", contractName)
	}

	eventKey := filter.Key
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

	eventAccountAddress, err := a.computeEventAccountAddress(address, eventConfig)
	if err != nil {
		return nil, err
	}

	eventHandle := address.String() + "::" + eventModuleName + "::" + eventConfig.EventHandleStructName
	if err := a.syncEvent(ctx, address, eventConfig, eventModuleName); err != nil {
		return nil, fmt.Errorf("syncEvent error: %w", err)
	}

	dbRecords, err := a.dbStore.QueryEvents(ctx, eventAccountAddress.String(), eventHandle, expressions, limitAndSort)
	if err != nil {
		return nil, fmt.Errorf("failed to query events from db: %w", err)
	}

	var sequences []types.Sequence
	for _, rec := range dbRecords {
		var eventData any
		if a.config.IsLoopPlugin {
			resultBytes, err := json.Marshal(rec.Data)
			if err != nil {
				return nil, fmt.Errorf("failed to re-marshal event data: %w", err)
			}

			eventData = &resultBytes
		} else {
			decoded := reflect.New(reflect.TypeOf(sequenceDataType).Elem()).Interface()

			if err := codec.DecodeAptosJsonValue(rec.Data, &decoded); err != nil {
				return nil, fmt.Errorf("failed to decode event data: %w", err)
			}

			eventData = decoded
		}

		sequence := types.Sequence{
			Cursor: fmt.Sprintf("%d", rec.ID),
			Head: types.Head{
				Height:    rec.BlockHeight,
				Hash:      rec.BlockHash,
				Timestamp: rec.BlockTimestamp,
			},
			Data: eventData,
		}
		sequences = append(sequences, sequence)
	}

	return sequences, nil
}

func (a *aptosChainReader) QueryKeyWithMetadata(ctx context.Context, contract types.BoundContract, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]SequenceWithMetadata, error) {
	seqs, err := a.QueryKey(ctx, contract, filter, limitAndSort, sequenceDataType)
	if err != nil {
		return nil, err
	}

	var enriched []SequenceWithMetadata
	for _, seq := range seqs {
		eventID, err := strconv.ParseUint(seq.Cursor, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid event id in cursor %q: %w", seq.Cursor, err)
		}

		txVersion, err := a.dbStore.GetTxVersionByID(ctx, eventID)
		if err != nil {
			return nil, err
		}

		tx, err := a.client.TransactionByVersion(txVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to get tx details for version %d: %w", txVersion, err)
		}

		enriched = append(enriched, SequenceWithMetadata{
			Sequence:  seq,
			TxVersion: txVersion,
			TxHash:    tx.Hash(),
		})
	}

	return enriched, nil
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

func (a *aptosChainReader) CreateContractType(readName string, forEncoding bool) (any, error) {
	// only called when LOOP plugin
	return &[]byte{}, nil
}

func (a *aptosChainReader) computeEventAccountAddress(boundAddress aptos.AccountAddress, eventConfig *ChainReaderEvent) (aptos.AccountAddress, error) {
	var eventAccountAddress aptos.AccountAddress
	if len(eventConfig.EventAccountAddress) == 0 {
		return boundAddress, nil
	}
	components := strings.Split(eventConfig.EventAccountAddress, "::")
	if len(components) == 1 {
		err := eventAccountAddress.ParseStringRelaxed(components[0])
		if err != nil {
			return eventAccountAddress, fmt.Errorf("failed to parse event account address: %+w", err)
		}
		return eventAccountAddress, nil
	} else {
		var addressFunctionAddress aptos.AccountAddress
		var addressFunctionModuleName, addressFunctionFunctionName string
		if len(components) == 3 {
			err := addressFunctionAddress.ParseStringRelaxed(components[0])
			if err != nil {
				return eventAccountAddress, fmt.Errorf("failed to parse event account address function address: %+w", err)
			}
			addressFunctionModuleName = components[1]
			addressFunctionFunctionName = components[2]
		} else if len(components) == 2 {
			addressFunctionAddress = boundAddress
			addressFunctionModuleName = components[0]
			addressFunctionFunctionName = components[1]
		} else {
			return eventAccountAddress, fmt.Errorf("invalid event account address definition: %s", eventConfig.EventAccountAddress)
		}
		cacheKey := addressFunctionAddress.String() + "::" + addressFunctionModuleName + "::" + addressFunctionFunctionName
		if cached, ok := a.eventAccountAddresses[cacheKey]; ok {
			return cached, nil
		}
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
			return eventAccountAddress, fmt.Errorf("failed to call view function: %+w", err)
		}
		err = codec.DecodeAptosJsonValue(data[0], &eventAccountAddress)
		if err != nil {
			return eventAccountAddress, fmt.Errorf("failed to decode event account address function output: %+w", err)
		}
		a.eventAccountAddresses[cacheKey] = eventAccountAddress
		return eventAccountAddress, nil
	}
}

func (a *aptosChainReader) getBlockHead(version uint64) (types.Head, error) {
	block, err := a.client.BlockByVersion(version, false)
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to get block by version: %w", err)
	}

	hexBytes, err := utils.DecodeHexRelaxed(block.BlockHash)
	if err != nil {
		return types.Head{}, fmt.Errorf("failed to decode block hash: %w", err)
	}

	head := types.Head{
		Height:    fmt.Sprintf("%d", block.BlockHeight),
		Hash:      hexBytes,
		Timestamp: block.BlockTimestamp / 1000000, // microseconds to seconds conversion
	}

	return head, nil
}
