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

	// Encoder returns the encoder implementation of this module.
	Encoder() MCMSUserEncoder
}

type MCMSUserEncoder interface {
	FunctionOne(arg1 string, arg2 []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	FunctionTwo(arg1 aptos.AccountAddress, arg2 *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"mcms_test","module":"mcms_user","name":"function_one","parameters":[{"name":"arg1","type":"0x1::string::String"},{"name":"arg2","type":"vector\u003cu8\u003e"}]},{"package":"mcms_test","module":"mcms_user","name":"function_two","parameters":[{"name":"arg1","type":"address"},{"name":"arg2","type":"u128"}]},{"package":"mcms_test","module":"mcms_user","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]}]`

func NewMCMSUser(address aptos.AccountAddress, client aptos.AptosRpcClient) MCMSUserInterface {
	contract := bind.NewBoundContract(address, "mcms_test", "mcms_user", client)
	return MCMSUserContract{
		BoundContract:   contract,
		mcmsUserEncoder: mcmsUserEncoder{BoundContract: contract},
	}
}

// Constants
const (
	EUNKNOWN_FUNCTION uint64 = 1
)

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

type MCMSUserContract struct {
	*bind.BoundContract
	mcmsUserEncoder
}

var _ MCMSUserInterface = MCMSUserContract{}

func (c MCMSUserContract) Encoder() MCMSUserEncoder {
	return c.mcmsUserEncoder
}

// View Functions

// Entry Functions

// Encoder
type mcmsUserEncoder struct {
	*bind.BoundContract
}

func (c mcmsUserEncoder) FunctionOne(arg1 string, arg2 []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("function_one", nil, []string{
		"0x1::string::String",
		"vector<u8>",
	}, []any{
		arg1,
		arg2,
	})
}

func (c mcmsUserEncoder) FunctionTwo(arg1 aptos.AccountAddress, arg2 *big.Int) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("function_two", nil, []string{
		"address",
		"u128",
	}, []any{
		arg1,
		arg2,
	})
}

func (c mcmsUserEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
