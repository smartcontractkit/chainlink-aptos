// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_lnr_registrar

import (
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

var (
	_ = aptos.AccountAddress{}
	_ = api.PendingTransaction{}
	_ = big.NewInt
	_ = bind.NewBoundContract
	_ = codec.DecodeAptosJsonValue
)

type LnrRegistrarInterface interface {
	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	InitializeWithoutTransferRef(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() LnrRegistrarEncoder
}

type LnrRegistrarEncoder interface {
	Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	InitializeWithoutTransferRef() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"test_token","module":"lnr_registrar","name":"initialize","parameters":null},{"package":"test_token","module":"lnr_registrar","name":"initialize_without_transfer_ref","parameters":null}]`

func NewLnrRegistrar(address aptos.AccountAddress, client aptos.AptosRpcClient) LnrRegistrarInterface {
	contract := bind.NewBoundContract(address, "test_token", "lnr_registrar", client)
	return LnrRegistrarContract{
		BoundContract:       contract,
		lnrRegistrarEncoder: lnrRegistrarEncoder{BoundContract: contract},
	}
}

// Structs

type LnrRegistrarContract struct {
	*bind.BoundContract
	lnrRegistrarEncoder
}

var _ LnrRegistrarInterface = LnrRegistrarContract{}

func (c LnrRegistrarContract) Encoder() LnrRegistrarEncoder {
	return c.lnrRegistrarEncoder
}

// View Functions

// Entry Functions

func (c LnrRegistrarContract) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.lnrRegistrarEncoder.Initialize()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c LnrRegistrarContract) InitializeWithoutTransferRef(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.lnrRegistrarEncoder.InitializeWithoutTransferRef()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type lnrRegistrarEncoder struct {
	*bind.BoundContract
}

func (c lnrRegistrarEncoder) Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{}, []any{})
}

func (c lnrRegistrarEncoder) InitializeWithoutTransferRef() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize_without_transfer_ref", nil, []string{}, []any{})
}
