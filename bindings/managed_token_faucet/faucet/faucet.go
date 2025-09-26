// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_faucet

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

type FaucetInterface interface {
	StateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)

	Drip(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() FaucetEncoder
}

type FaucetEncoder interface {
	StateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Drip(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"managed_token","module":"faucet","name":"drip","parameters":[{"name":"to","type":"address"}]}]`

func NewFaucet(address aptos.AccountAddress, client aptos.AptosRpcClient) FaucetInterface {
	contract := bind.NewBoundContract(address, "managed_token", "faucet", client)
	return FaucetContract{
		BoundContract: contract,
		faucetEncoder: faucetEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_NOT_PUBLISHER uint64 = 1
)

// Structs

type FaucetState struct {
}

type FaucetContract struct {
	*bind.BoundContract
	faucetEncoder
}

var _ FaucetInterface = FaucetContract{}

func (c FaucetContract) Encoder() FaucetEncoder {
	return c.faucetEncoder
}

// View Functions

func (c FaucetContract) StateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.faucetEncoder.StateAddress()
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(aptos.AccountAddress), err
	}

	var (
		r0 aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(aptos.AccountAddress), err
	}
	return r0, nil
}

// Entry Functions

func (c FaucetContract) Drip(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.faucetEncoder.Drip(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type faucetEncoder struct {
	*bind.BoundContract
}

func (c faucetEncoder) StateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("state_address", nil, []string{}, []any{})
}

func (c faucetEncoder) Drip(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("drip", nil, []string{
		"address",
	}, []any{
		to,
	})
}
