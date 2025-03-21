// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_mcms_user

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

type MCMSUserInterface interface {
}

// Structs

type UserData struct {
	Invocations byte                 `move:"u8"`
	A           string               `move:"0x1::string::String"`
	B           []byte               `move:"vector<u8>"`
	C           aptos.AccountAddress `move:"address"`
	D           *big.Int             `move:"u128"`
}

type SampleMcmsCallback struct {
}

type MCMSUser struct {
	MCMSUserCaller
	MCMSUserTransactor
}

// View Functions

type MCMSUserCaller struct {
	*bind.BoundContract
}

// Entry Functions

type MCMSUserTransactor struct {
	*bind.BoundContract
}
