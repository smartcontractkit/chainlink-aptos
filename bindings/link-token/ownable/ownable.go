// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_ownable

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

type OwnableInterface interface {

	// Encoder returns the encoder implementation of this module.
	Encoder() OwnableEncoder
}

type OwnableEncoder interface {
	New(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"link","module":"ownable","name":"new","parameters":[{"name":"object_address","type":"address"}]}]`

func NewOwnable(address aptos.AccountAddress, client aptos.AptosRpcClient) OwnableInterface {
	contract := bind.NewBoundContract(address, "link", "ownable", client)
	return OwnableContract{
		BoundContract:  contract,
		ownableEncoder: ownableEncoder{BoundContract: contract},
	}
}

// Structs

type OwnableState struct {
	TargetObject    bind.StdObject   `move:"aptos_framework::object::Object"`
	PendingTransfer *PendingTransfer `move:"std::option::Option<PendingTransfer>"`
}

type PendingTransfer struct {
	From     aptos.AccountAddress `move:"address"`
	To       aptos.AccountAddress `move:"address"`
	Accepted bool                 `move:"bool"`
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferAccepted struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferred struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnableContract struct {
	*bind.BoundContract
	ownableEncoder
}

var _ OwnableInterface = OwnableContract{}

func (c OwnableContract) Encoder() OwnableEncoder {
	return c.ownableEncoder
}

// View Functions

// Entry Functions

// Encoder
type ownableEncoder struct {
	*bind.BoundContract
}

func (c ownableEncoder) New(objectAddress aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{
		"address",
	}, []any{
		objectAddress,
	})
}
