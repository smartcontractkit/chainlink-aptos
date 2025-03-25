package bind

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/relayer/txm"
)

// Event is an interface that all events must implement.
type Event interface {
	EventName() string
}

/*
TODO
	Add per-request context once supported by aptos-go-sdk: https://github.com/aptos-labs/aptos-go-sdk/issues/95
*/

type CallOpts struct {
	// Optional ledger version to query at. If nil, the latest ledger version is used.
	LedgerVersion *uint64
}

type TransactOpts struct {
	Signer aptos.TransactionSigner

	MaxGasAmount      *uint64
	GasUnitPrice      *uint64
	ExpirationSeconds *uint64
	SequenceNumber    *uint64
}

type ModuleInformation struct {
	PackageName string
	ModuleName  string
	Address     aptos.AccountAddress
}

type BoundContract struct {
	address                 aptos.AccountAddress
	packageName, moduleName string
	client                  aptos.AptosRpcClient
}

func NewBoundContract(address aptos.AccountAddress, packageName, moduleName string, client aptos.AptosRpcClient) *BoundContract {
	return &BoundContract{
		address:     address,
		packageName: packageName,
		moduleName:  moduleName,
		client:      client,
	}
}

func (c *BoundContract) Encode(function string, typeArgs, paramTypes []string, paramValues []any) (moduleInfo ModuleInformation, fun string, argTypes []aptos.TypeTag, args [][]byte, err error) {
	typeTags, args, err := serializeArgs(typeArgs, paramTypes, paramValues)
	if err != nil {
		return ModuleInformation{}, "", nil, nil, err
	}

	return ModuleInformation{
		PackageName: c.packageName,
		ModuleName:  c.moduleName,
		Address:     c.address,
	}, function, typeTags, args, nil
}

func (c *BoundContract) Call(opts *CallOpts, module ModuleInformation, function string, argTypes []aptos.TypeTag, args [][]byte) ([]any, error) {
	payload := aptos.ViewPayload{
		Module: aptos.ModuleId{
			Address: module.Address,
			Name:    module.ModuleName,
		},
		Function: function,
		ArgTypes: argTypes,
		Args:     args,
	}

	// opts are optional
	var ledgerVersion []uint64
	if opts != nil && opts.LedgerVersion != nil {
		ledgerVersion = append(ledgerVersion, *opts.LedgerVersion)
	}

	return c.client.View(&payload, ledgerVersion...)
}

func (c *BoundContract) Transact(opts *TransactOpts, module ModuleInformation, function string, argTypes []aptos.TypeTag, args [][]byte) (*api.PendingTransaction, error) {
	payload := aptos.TransactionPayload{Payload: &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: module.Address,
			Name:    module.ModuleName,
		},
		Function: function,
		ArgTypes: argTypes,
		Args:     args,
	}}

	if opts == nil {
		return nil, fmt.Errorf("TransactOpts must be provided")
	}
	if opts.Signer == nil {
		return nil, fmt.Errorf("TransactOpts.Signer must be provided")
	}

	var options []any
	if opts.MaxGasAmount != nil {
		options = append(options, aptos.MaxGasAmount(*opts.MaxGasAmount))
	}
	if opts.GasUnitPrice != nil {
		options = append(options, aptos.GasUnitPrice(*opts.GasUnitPrice))
	}
	if opts.ExpirationSeconds != nil {
		options = append(options, aptos.ExpirationSeconds(*opts.ExpirationSeconds))
	}
	if opts.SequenceNumber != nil {
		options = append(options, aptos.SequenceNumber(*opts.SequenceNumber))
	}

	return c.client.BuildSignAndSubmitTransaction(opts.Signer, payload, options...)
}

func serializeArgs(argTypes, paramTypes []string, paramValues []any) ([]aptos.TypeTag, [][]byte, error) {
	if len(paramValues) != len(paramTypes) {
		return nil, nil, fmt.Errorf("paramTypes and paramValues must have the same length")
	}

	typeTags := make([]aptos.TypeTag, len(argTypes))
	args := make([][]byte, len(paramTypes))

	for i, arg := range argTypes {
		typeTag, err := txm.CreateTypeTag(arg)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse type argument %q: %w", arg, err)
		}
		typeTags[i] = typeTag
	}
	for i := range paramTypes {
		typeName := paramTypes[i]
		typeValue := paramValues[i]

		typeTag, err := txm.CreateTypeTag(typeName)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse type %q: %w", typeName, err)
		}

		bcsValue, err := txm.CreateBcsValue(typeTag, typeValue)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to serialize value #%v typeTag: %v typeValue: %v type :%T: %w", i, typeTag.String(), typeValue, typeValue, err)
		}
		args[i] = bcsValue
	}

	return typeTags, args, nil
}
