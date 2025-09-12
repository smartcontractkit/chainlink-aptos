// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_bnm_registrar

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

type BnmRegistrarInterface interface {
	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() BnmRegistrarEncoder
}

type BnmRegistrarEncoder interface {
	Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"test_token","module":"bnm_registrar","name":"initialize","parameters":null}]`

func NewBnmRegistrar(address aptos.AccountAddress, client aptos.AptosRpcClient) BnmRegistrarInterface {
	contract := bind.NewBoundContract(address, "test_token", "bnm_registrar", client)
	return BnmRegistrarContract{
		BoundContract:       contract,
		bnmRegistrarEncoder: bnmRegistrarEncoder{BoundContract: contract},
	}
}

// Structs

type BnmRegistrarContract struct {
	*bind.BoundContract
	bnmRegistrarEncoder
}

var _ BnmRegistrarInterface = BnmRegistrarContract{}

func (c BnmRegistrarContract) Encoder() BnmRegistrarEncoder {
	return c.bnmRegistrarEncoder
}

// View Functions

// Entry Functions

func (c BnmRegistrarContract) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.bnmRegistrarEncoder.Initialize()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type bnmRegistrarEncoder struct {
	*bind.BoundContract
}

func (c bnmRegistrarEncoder) Initialize() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{}, []any{})
}
