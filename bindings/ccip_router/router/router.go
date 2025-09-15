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
	TypeAndVersion(opts *bind.CallOpts) (string, error)
	GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error)
	GetOnRamp(opts *bind.CallOpts, destChainSelector uint64) (aptos.AccountAddress, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)
	GetOnRampVersions(opts *bind.CallOpts, destChainSelectors []uint64) ([][]byte, error)
	GetOnRampForVersion(opts *bind.CallOpts, onRampVersion []byte) (aptos.AccountAddress, error)
	GetDestChains(opts *bind.CallOpts) ([]uint64, error)
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	HasPendingTransfer(opts *bind.CallOpts) (bool, error)
	PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error)
	PendingTransferAccepted(opts *bind.CallOpts) (*bool, error)

	CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error)
	SetOnRampVersions(opts *bind.TransactOpts, destChainSelectors []uint64, onRampVersions [][]byte) (*api.PendingTransaction, error)
	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptOwnership(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() RouterEncoder
}

type RouterEncoder interface {
	TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOnRamp(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOnRampVersions(destChainSelectors []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetOnRampForVersion(onRampVersion []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetDestChains() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	SetOnRampVersions(destChainSelectors []uint64, onRampVersions [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	TransferOwnership(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	AcceptOwnership() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CCIPSendWithMessageId(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_router","module":"router","name":"accept_ownership","parameters":null},{"package":"ccip_router","module":"router","name":"ccip_send","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip_router","module":"router","name":"ccip_send_with_message_id","parameters":[{"name":"dest_chain_selector","type":"u64"},{"name":"receiver","type":"vector\u003cu8\u003e"},{"name":"data","type":"vector\u003cu8\u003e"},{"name":"token_addresses","type":"vector\u003caddress\u003e"},{"name":"token_amounts","type":"vector\u003cu64\u003e"},{"name":"token_store_addresses","type":"vector\u003caddress\u003e"},{"name":"fee_token","type":"address"},{"name":"fee_token_store","type":"address"},{"name":"extra_args","type":"vector\u003cu8\u003e"}]},{"package":"ccip_router","module":"router","name":"execute_ownership_transfer","parameters":[{"name":"to","type":"address"}]},{"package":"ccip_router","module":"router","name":"get_state_address_internal","parameters":null},{"package":"ccip_router","module":"router","name":"mcms_entrypoint","parameters":[{"name":"_metadata","type":"address"}]},{"package":"ccip_router","module":"router","name":"set_on_ramp_versions","parameters":[{"name":"dest_chain_selectors","type":"vector\u003cu64\u003e"},{"name":"on_ramp_versions","type":"vector\u003cvector\u003cu8\u003e\u003e"}]},{"package":"ccip_router","module":"router","name":"transfer_ownership","parameters":[{"name":"to","type":"address"}]}]`

func NewRouter(address aptos.AccountAddress, client aptos.AptosRpcClient) RouterInterface {
	contract := bind.NewBoundContract(address, "ccip_router", "router", client)
	return RouterContract{
		BoundContract: contract,
		routerEncoder: routerEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_UNKNOWN_FUNCTION              uint64 = 1
	E_UNSUPPORTED_DESTINATION_CHAIN uint64 = 2
	E_UNSUPPORTED_ON_RAMP_VERSION   uint64 = 3
	E_INVALID_ON_RAMP_VERSION       uint64 = 4
	E_SET_ON_RAMP_VERSIONS_MISMATCH uint64 = 5
)

// Structs

type RouterState struct {
}

type OnRampSet struct {
	DestChainSelector uint64 `move:"u64"`
	OnRampVersion     []byte `move:"vector<u8>"`
}

type McmsCallback struct {
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

func (c RouterContract) TypeAndVersion(opts *bind.CallOpts) (string, error) {
	module, function, typeTags, args, err := c.routerEncoder.TypeAndVersion()
	if err != nil {
		return *new(string), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(string), err
	}

	var (
		r0 string
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(string), err
	}
	return r0, nil
}

func (c RouterContract) GetStateAddress(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetStateAddress()
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

func (c RouterContract) IsChainSupported(opts *bind.CallOpts, destChainSelector uint64) (bool, error) {
	module, function, typeTags, args, err := c.routerEncoder.IsChainSupported(destChainSelector)
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RouterContract) GetOnRamp(opts *bind.CallOpts, destChainSelector uint64) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetOnRamp(destChainSelector)
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

func (c RouterContract) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetFee(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return *new(uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(uint64), err
	}

	var (
		r0 uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(uint64), err
	}
	return r0, nil
}

func (c RouterContract) GetOnRampVersions(opts *bind.CallOpts, destChainSelectors []uint64) ([][]byte, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetOnRampVersions(destChainSelectors)
	if err != nil {
		return *new([][]byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([][]byte), err
	}

	var (
		r0 [][]byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([][]byte), err
	}
	return r0, nil
}

func (c RouterContract) GetOnRampForVersion(opts *bind.CallOpts, onRampVersion []byte) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetOnRampForVersion(onRampVersion)
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

func (c RouterContract) GetDestChains(opts *bind.CallOpts) ([]uint64, error) {
	module, function, typeTags, args, err := c.routerEncoder.GetDestChains()
	if err != nil {
		return *new([]uint64), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new([]uint64), err
	}

	var (
		r0 []uint64
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new([]uint64), err
	}
	return r0, nil
}

func (c RouterContract) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.Owner()
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

func (c RouterContract) HasPendingTransfer(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := c.routerEncoder.HasPendingTransfer()
	if err != nil {
		return *new(bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(bool), err
	}

	var (
		r0 bool
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(bool), err
	}
	return r0, nil
}

func (c RouterContract) PendingTransferFrom(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.PendingTransferFrom()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c RouterContract) PendingTransferTo(opts *bind.CallOpts) (*aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.routerEncoder.PendingTransferTo()
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*aptos.AccountAddress), err
	}

	var (
		r0 bind.StdOption[aptos.AccountAddress]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*aptos.AccountAddress), err
	}
	return r0.Value(), nil
}

func (c RouterContract) PendingTransferAccepted(opts *bind.CallOpts) (*bool, error) {
	module, function, typeTags, args, err := c.routerEncoder.PendingTransferAccepted()
	if err != nil {
		return *new(*bool), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*bool), err
	}

	var (
		r0 bind.StdOption[bool]
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*bool), err
	}
	return r0.Value(), nil
}

// Entry Functions

func (c RouterContract) CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.CCIPSend(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

func (c RouterContract) SetOnRampVersions(opts *bind.TransactOpts, destChainSelectors []uint64, onRampVersions [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.SetOnRampVersions(destChainSelectors, onRampVersions)
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

func (c RouterContract) ExecuteOwnershipTransfer(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := c.routerEncoder.ExecuteOwnershipTransfer(to)
	if err != nil {
		return nil, err
	}

	return c.BoundContract.Transact(opts, module, function, typeTags, args)
}

// Encoder
type routerEncoder struct {
	*bind.BoundContract
}

func (c routerEncoder) TypeAndVersion() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("type_and_version", nil, []string{}, []any{})
}

func (c routerEncoder) GetStateAddress() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address", nil, []string{}, []any{})
}

func (c routerEncoder) IsChainSupported(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("is_chain_supported", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c routerEncoder) GetOnRamp(destChainSelector uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_on_ramp", nil, []string{
		"u64",
	}, []any{
		destChainSelector,
	})
}

func (c routerEncoder) GetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_fee", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}

func (c routerEncoder) GetOnRampVersions(destChainSelectors []uint64) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_on_ramp_versions", nil, []string{
		"vector<u64>",
	}, []any{
		destChainSelectors,
	})
}

func (c routerEncoder) GetOnRampForVersion(onRampVersion []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_on_ramp_for_version", nil, []string{
		"vector<u8>",
	}, []any{
		onRampVersion,
	})
}

func (c routerEncoder) GetDestChains() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_dest_chains", nil, []string{}, []any{})
}

func (c routerEncoder) Owner() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("owner", nil, []string{}, []any{})
}

func (c routerEncoder) HasPendingTransfer() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("has_pending_transfer", nil, []string{}, []any{})
}

func (c routerEncoder) PendingTransferFrom() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_from", nil, []string{}, []any{})
}

func (c routerEncoder) PendingTransferTo() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_to", nil, []string{}, []any{})
}

func (c routerEncoder) PendingTransferAccepted() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("pending_transfer_accepted", nil, []string{}, []any{})
}

func (c routerEncoder) CCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ccip_send", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}

func (c routerEncoder) SetOnRampVersions(destChainSelectors []uint64, onRampVersions [][]byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("set_on_ramp_versions", nil, []string{
		"vector<u64>",
		"vector<vector<u8>>",
	}, []any{
		destChainSelectors,
		onRampVersions,
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

func (c routerEncoder) ExecuteOwnershipTransfer(to aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("execute_ownership_transfer", nil, []string{
		"address",
	}, []any{
		to,
	})
}

func (c routerEncoder) CCIPSendWithMessageId(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("ccip_send_with_message_id", nil, []string{
		"u64",
		"vector<u8>",
		"vector<u8>",
		"vector<address>",
		"vector<u64>",
		"vector<address>",
		"address",
		"address",
		"vector<u8>",
	}, []any{
		destChainSelector,
		receiver,
		data,
		tokenAddresses,
		tokenAmounts,
		tokenStoreAddresses,
		feeToken,
		feeTokenStore,
		extraArgs,
	})
}

func (c routerEncoder) GetStateAddressInternal() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_state_address_internal", nil, []string{}, []any{})
}

func (c routerEncoder) MCMSEntrypoint(Metadata aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("mcms_entrypoint", nil, []string{
		"address",
	}, []any{
		Metadata,
	})
}
