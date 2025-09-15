// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_allowlist

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

type AllowlistInterface interface {

	// Encoder returns the encoder implementation of this module.
	Encoder() AllowlistEncoder
}

type AllowlistEncoder interface {
	New(allowlist []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	NewWithName(allowlist []aptos.AccountAddress, allowlistName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	DestroyAllowlist(state AllowlistState) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"managed_token","module":"allowlist","name":"destroy_allowlist","parameters":[{"name":"state","type":"AllowlistState"}]},{"package":"managed_token","module":"allowlist","name":"new","parameters":[{"name":"allowlist","type":"vector\u003caddress\u003e"}]},{"package":"managed_token","module":"allowlist","name":"new_with_name","parameters":[{"name":"allowlist","type":"vector\u003caddress\u003e"},{"name":"allowlist_name","type":"0x1::string::String"}]}]`

func NewAllowlist(address aptos.AccountAddress, client aptos.AptosRpcClient) AllowlistInterface {
	contract := bind.NewBoundContract(address, "managed_token", "allowlist", client)
	return AllowlistContract{
		BoundContract:    contract,
		allowlistEncoder: allowlistEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_ALLOWLIST_NOT_ENABLED uint64 = 1
)

// Structs

type AllowlistState struct {
	AllowlistName    string                 `move:"0x1::string::String"`
	AllowlistEnabled bool                   `move:"bool"`
	Allowlist        []aptos.AccountAddress `move:"vector<address>"`
}

type AllowlistRemove struct {
	AllowlistName string               `move:"0x1::string::String"`
	Sender        aptos.AccountAddress `move:"address"`
}

type AllowlistAdd struct {
	AllowlistName string               `move:"0x1::string::String"`
	Sender        aptos.AccountAddress `move:"address"`
}

type AllowlistContract struct {
	*bind.BoundContract
	allowlistEncoder
}

var _ AllowlistInterface = AllowlistContract{}

func (c AllowlistContract) Encoder() AllowlistEncoder {
	return c.allowlistEncoder
}

// View Functions

// Entry Functions

// Encoder
type allowlistEncoder struct {
	*bind.BoundContract
}

func (c allowlistEncoder) New(allowlist []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new", nil, []string{
		"vector<address>",
	}, []any{
		allowlist,
	})
}

func (c allowlistEncoder) NewWithName(allowlist []aptos.AccountAddress, allowlistName string) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("new_with_name", nil, []string{
		"vector<address>",
		"0x1::string::String",
	}, []any{
		allowlist,
		allowlistName,
	})
}

func (c allowlistEncoder) DestroyAllowlist(state AllowlistState) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("destroy_allowlist", nil, []string{
		"AllowlistState",
	}, []any{
		state,
	})
}
