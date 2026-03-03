package loop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query"
	"github.com/smartcontractkit/chainlink-common/pkg/types/query/primitives"
)

const maxResponseSize = 4 * 1024 * 1024 // 4MB

// NewLoopChainReader creates a ContractReader that wraps an existing ContractReader
// to work across LOOP boundaries.
//
// The wrapper provides:
// - Contract name to module address mapping
// - JSON serialization/deserialization for LOOP communication
// - Automatic contract re-binding for LOOP plugin restarts
//
// Both `logger` and `cr` parameters must be non-nil.
func NewLoopChainReader(logger logger.Logger, cr types.ContractReader) types.ContractReader {
	return &loopChainReader{logger: logger, cr: cr, moduleAddresses: map[string]string{}}
}

type loopChainReader struct {
	services.Service
	types.UnimplementedContractReader
	logger            logger.Logger
	cr                types.ContractReader
	moduleAddressesMu sync.RWMutex
	moduleAddresses   map[string]string
}

func (a *loopChainReader) Name() string {
	return a.cr.Name()
}

func (a *loopChainReader) Ready() error {
	return a.cr.Ready()
}

func (a *loopChainReader) HealthReport() map[string]error {
	return a.cr.HealthReport()
}

func (a *loopChainReader) Start(ctx context.Context) error {
	return a.cr.Start(ctx)
}

func (a *loopChainReader) Close() error {
	return a.cr.Close()
}

func (a *loopChainReader) GetLatestValue(ctx context.Context, readIdentifier string, confidenceLevel primitives.ConfidenceLevel, params, returnVal any) error {
	readComponents := strings.Split(readIdentifier, "-")
	if len(readComponents) != 3 {
		return fmt.Errorf("invalid read identifier: %s", readIdentifier)
	}

	_, contractName, _ := readComponents[0], readComponents[1], readComponents[2]

	ok := a.hasModuleAddress(contractName)
	if !ok {
		return fmt.Errorf("no such contract: %s", contractName)
	}

	convertedResult := []byte{}

	jsonParamBytes, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %+w", err)
	}

	// we always bind before calling query functions, because the LOOP plugin may have restarted.
	err = a.cr.Bind(ctx, a.getBindings())
	if err != nil {
		return fmt.Errorf("failed to re-bind before GetLatestValue: %w", err)
	}

	err = a.cr.GetLatestValue(ctx, readIdentifier, confidenceLevel, &jsonParamBytes, &convertedResult)
	if err != nil {
		return fmt.Errorf("failed to call GetLatestValue over LOOP: %w", err)
	}

	err = a.decodeGLVReturnValue(readIdentifier, convertedResult, returnVal)
	if err != nil {
		return fmt.Errorf("failed to decode GetLatestValue return value: %w", err)
	}

	return nil
}

func (a *loopChainReader) BatchGetLatestValues(ctx context.Context, request types.BatchGetLatestValuesRequest) (types.BatchGetLatestValuesResult, error) {
	convertedRequest := types.BatchGetLatestValuesRequest{}
	for contract, requestBatch := range request {
		convertedBatch := []types.BatchRead{}
		for _, read := range requestBatch {
			ok := a.hasModuleAddress(contract.Name)
			if !ok {
				return nil, fmt.Errorf("no such contract: %s", contract.Name)
			}

			jsonParamBytes, err := json.Marshal(read.Params)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal params: %+w", err)
			}
			convertedBatch = append(convertedBatch, types.BatchRead{
				ReadName:  read.ReadName,
				Params:    jsonParamBytes,
				ReturnVal: &[]byte{},
			})
		}
		convertedRequest[contract] = convertedBatch
	}

	// we always bind before calling query functions, because the LOOP plugin may have restarted.
	err := a.cr.Bind(ctx, a.getBindings())
	if err != nil {
		return nil, fmt.Errorf("failed to re-bind before BatchGetLatestValues: %w", err)
	}

	result, err := a.cr.BatchGetLatestValues(ctx, convertedRequest)
	if err != nil {
		return nil, err
	}

	convertedResult := types.BatchGetLatestValuesResult{}
	for contract, resultBatch := range result {
		requestBatch := request[contract]
		convertedBatch := []types.BatchReadResult{}
		for i, result := range resultBatch {
			read := requestBatch[i]
			resultValue, resultError := result.GetResult()
			convertedResult := types.BatchReadResult{ReadName: result.ReadName}
			if resultError == nil {
				resultPointer := resultValue.(*[]byte)
				err := a.decodeGLVReturnValue(result.ReadName, *resultPointer, read.ReturnVal)
				if err != nil {
					resultError = fmt.Errorf("failed to decode BatchGetLatestValue return value: %w", err)
				}
			}
			convertedResult.SetResult(read.ReturnVal, resultError)
			convertedBatch = append(convertedBatch, convertedResult)
		}
		convertedResult[contract] = convertedBatch
	}

	return convertedResult, nil
}

func (a *loopChainReader) QueryKey(ctx context.Context, contract types.BoundContract, filter query.KeyFilter, limitAndSort query.LimitAndSort, sequenceDataType any) ([]types.Sequence, error) {
	err := a.cr.Bind(ctx, a.getBindings())
	if err != nil {
		return nil, fmt.Errorf("failed to re-bind before QueryKey: %w", err)
	}

	convertedExpressions, err := SerializeExpressions(filter.Expressions)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize QueryKey expressions: %w", err)
	}

	convertedFilter := query.KeyFilter{
		Key:         filter.Key,
		Expressions: convertedExpressions,
	}

	sequences, err := a.cr.QueryKey(ctx, contract, convertedFilter, limitAndSort, &[]byte{})
	if err != nil {
		return nil, fmt.Errorf("failed to call QueryKey over LOOP: %w", err)
	}

	for i, sequence := range sequences {
		jsonBytes, ok := sequence.Data.(*[]byte)
		if !ok {
			return nil, fmt.Errorf("expected sequence.Data to be of type *[]byte, got %T", sequence.Data)
		}

		if len(*jsonBytes) > maxResponseSize {
			return nil, fmt.Errorf("sequence data response size (%d bytes) exceeds maximum allowed size (%d bytes)", len(*jsonBytes), maxResponseSize)
		}

		jsonData := map[string]any{}
		err := json.Unmarshal(*jsonBytes, &jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal LOOP sourced JSON event data (`%s`): %w", string(*jsonBytes), err)
		}

		if sequenceDataType == nil {
			return nil, errors.New("sequence data type is nil")
		}

		eventData := reflect.New(reflect.TypeOf(sequenceDataType).Elem()).Interface()
		err = codec.DecodeAptosJsonValue(jsonData, eventData)
		if err != nil {
			return nil, fmt.Errorf("failed to decode LOOP sourced event data (`%s`) into an Aptos value: %+w", string(*jsonBytes), err)
		}

		sequences[i].Data = eventData
	}

	return sequences, nil
}

func (a *loopChainReader) Bind(ctx context.Context, bindings []types.BoundContract) error {
	a.moduleAddressesMu.Lock()
	for _, binding := range bindings {
		a.moduleAddresses[binding.Name] = binding.Address
	}
	a.moduleAddressesMu.Unlock()

	return a.cr.Bind(ctx, bindings)
}

func (a *loopChainReader) Unbind(ctx context.Context, bindings []types.BoundContract) error {
	a.moduleAddressesMu.Lock()
	for _, binding := range bindings {
		key := binding.Name
		if _, ok := a.moduleAddresses[key]; ok {
			delete(a.moduleAddresses, key)
		} else {
			a.moduleAddressesMu.Unlock()
			return fmt.Errorf("no such binding: %s", key)
		}
	}
	a.moduleAddressesMu.Unlock()

	// we ignore unbind errors, because if the LOOP plugin restarted, the binding would not exist.
	err := a.cr.Unbind(ctx, bindings)
	if err != nil {
		a.logger.Warnw("failed to unbind bindings", "err", err)
	}

	return nil
}

func (a *loopChainReader) getBindings() []types.BoundContract {
	a.moduleAddressesMu.RLock()
	defer a.moduleAddressesMu.RUnlock()

	bindings := make([]types.BoundContract, 0, len(a.moduleAddresses))

	for name, address := range a.moduleAddresses {
		bindings = append(bindings, types.BoundContract{
			Address: address,
			Name:    name,
		})
	}

	return bindings
}

func (a *loopChainReader) hasModuleAddress(name string) bool {
	a.moduleAddressesMu.RLock()
	defer a.moduleAddressesMu.RUnlock()

	_, ok := a.moduleAddresses[name]
	return ok
}

func (a *loopChainReader) decodeGLVReturnValue(label string, jsonBytes []byte, returnVal any) error {
	if len(jsonBytes) > maxResponseSize {
		return fmt.Errorf("getLatestValue response size (%d bytes) exceeds maximum allowed size (%d bytes)", len(jsonBytes), maxResponseSize)
	}

	var result any
	err := json.Unmarshal(jsonBytes, &result)
	if err != nil {
		return fmt.Errorf("failed to unmarshal %s GetLatestValue result (`%s`): %w", label, string(jsonBytes), err)
	}

	err = codec.DecodeAptosJsonValue(result, returnVal)
	if err != nil {
		return fmt.Errorf("failed to decode %s GetLatestValue JSON value (`%s`) to %T: %w", label, string(jsonBytes), returnVal, err)
	}

	return nil
}
