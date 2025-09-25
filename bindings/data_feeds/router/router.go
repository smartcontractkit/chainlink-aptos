// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_router

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

type RouterInterface interface {
	GetDescriptions(opts *bind.CallOpts, feedIds [][]byte) ([]string, error)
	GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error)

	ConfigureFeeds(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string, configId []byte, FeeConfigId []byte) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RouterEncoder
}

type RouterEncoder interface {
	GetDescriptions(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ConfigureFeeds(feedIds [][]byte, descriptions []string, configId []byte, FeeConfigId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"data_feeds","module":"router","name":"accept_ownership","parameters":null},{"package":"data_feeds","module":"router","name":"configure_feeds","parameters":[{"name":"feed_ids","type":"vector\u003cvector\u003cu8\u003e\u003e"},{"name":"descriptions","type":"vector\u003c0x1::string::String\u003e"},{"name":"config_id","type":"vector\u003cu8\u003e"},{"name":"_fee_config_id","type":"vector\u003cu8\u003e"}]},{"package":"data_feeds","module":"router","name":"get_state_addr","parameters":null},{"package":"data_feeds","module":"router","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewRouter(address aptos.AccountAddress, client aptos.AptosRpcClient) RouterInterface {
	contract := bind.NewBoundContract(address, "data_feeds", "router", client)
	return RouterContract{
		BoundContract: contract,
		routerEncoder: routerEncoder{BoundContract: contract},
	}
}

// Constants
const (
	ENOT_OWNER               uint64 = 0
	ECANNOT_TRANSFER_TO_SELF uint64 = 1
	ENOT_PROPOSED_OWNER      uint64 = 2
	EREPORTS_DEPRECATED      uint64 = 3
)

// Structs

type Router struct {
	OwnerAddress        aptos.AccountAddress `move:"address"`
	PendingOwnerAddress aptos.AccountAddress `move:"address"`
}

type OwnershipTransferRequested struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type OwnershipTransferred struct {
	From aptos.AccountAddress `move:"address"`
	To   aptos.AccountAddress `move:"address"`
}

type FeedRead struct {
	FeedIds [][]byte `move:"vector<vector<u8>>"`
}

type RouterContract struct {
	*bind.BoundContract
	routerEncoder
}

var _ RouterInterface = RouterContract{}

func (c RouterContract) Encoder() RouterEncoder {
	return c.routerEncoder
}

// View Functions

func (c RouterContract) GetDescriptions(opts *bind.CallOpts, feedIds [][]byte) ([]string, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetDescriptions(feedIds)
	if err != nil {
		return *new([]string), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]string), err
	}

	var (
		r0 []string
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]string), err
	}
	return r0, nil
}

func (c RouterContract) GetOwner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetOwner()
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

func (c RouterContract) ConfigureFeeds(opts *bind.TransactOpts, feedIds [][]byte, descriptions []string, configId []byte, FeeConfigId []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.ConfigureFeeds(feedIds, descriptions, configId, FeeConfigId)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RouterContract) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.TransferOwnership(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RouterContract) AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.AcceptOwnership()
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type routerEncoder struct {
	*bind.BoundContract
}

func (c routerEncoder) GetDescriptions(feedIds [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_descriptions", nil, []string{
		"vector<vector<u8>>",
	}, []any{
		feedIds,
	})
}

func (c routerEncoder) GetOwner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_owner", nil, []string{}, []any{})
}

func (c routerEncoder) ConfigureFeeds(feedIds [][]byte, descriptions []string, configId []byte, FeeConfigId []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("configure_feeds", nil, []string{
		"vector<vector<u8>>",
		"vector<0x1::string::String>",
		"vector<u8>",
		"vector<u8>",
	}, []any{
		feedIds,
		descriptions,
		configId,
		FeeConfigId,
	})
}

func (c routerEncoder) TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("transfer_ownership", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c routerEncoder) AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("accept_ownership", nil, []string{}, []any{})
}

func (c routerEncoder) GetStateAddr() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_addr", nil, []string{}, []any{})
}
