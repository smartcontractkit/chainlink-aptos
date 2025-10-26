// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package module_token_pool

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

type TokenPoolInterface interface {
	GetRouter(opts *bind.CallOpts) (aptos.AccountAddress, error)
	ParseRemoteDecimals(opts *bind.CallOpts, sourcePoolData []byte, localDecimals byte) (byte, error)
	CalculateLocalAmount(opts *bind.CallOpts, remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (uint64, error)
	CalculateLocalAmountInternal(opts *bind.CallOpts, remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (*big.Int, error)

	// Encoder returns the encoder implementation of this module.
	Encoder() TokenPoolEncoder
}

type TokenPoolEncoder interface {
	GetRouter() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	ParseRemoteDecimals(sourcePoolData []byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateLocalAmount(remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	CalculateLocalAmountInternal(remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
	Initialize(localToken aptos.AccountAddress, allowlist []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error)
}

const FunctionInfo = `[{"package":"ccip_token_pool","module":"token_pool","name":"initialize","parameters":[{"name":"local_token","type":"address"},{"name":"allowlist","type":"vector\u003caddress\u003e"}]}]`

func NewTokenPool(address aptos.AccountAddress, client aptos.AptosRpcClient) TokenPoolInterface {
	contract := bind.NewBoundContract(address, "ccip_token_pool", "token_pool", client)
	return TokenPoolContract{
		BoundContract:    contract,
		tokenPoolEncoder: tokenPoolEncoder{BoundContract: contract},
	}
}

// Constants
const (
	E_NOT_ALLOWED_CALLER            uint64 = 1
	E_UNKNOWN_FUNGIBLE_ASSET        uint64 = 2
	E_UNKNOWN_REMOTE_CHAIN_SELECTOR uint64 = 3
	E_ZERO_ADDRESS_NOT_ALLOWED      uint64 = 4
	E_REMOTE_POOL_ALREADY_ADDED     uint64 = 5
	E_UNKNOWN_REMOTE_POOL           uint64 = 6
	E_REMOTE_CHAIN_TO_ADD_MISMATCH  uint64 = 7
	E_REMOTE_CHAIN_ALREADY_EXISTS   uint64 = 8
	E_INVALID_REMOTE_CHAIN_DECIMALS uint64 = 9
	E_INVALID_ENCODED_AMOUNT        uint64 = 10
	E_DECIMAL_OVERFLOW              uint64 = 11
	E_CURSED_CHAIN                  uint64 = 12
)

// Structs

type TokenPoolState struct {
	FaMetadata bind.StdObject `move:"aptos_framework::object::Object"`
}

type RemoteChainConfig struct {
	RemoteTokenAddress []byte   `move:"vector<u8>"`
	RemotePools        [][]byte `move:"vector<vector<u8>>"`
}

type LockedOrBurned struct {
	RemoteChainSelector uint64               `move:"u64"`
	LocalToken          aptos.AccountAddress `move:"address"`
	Amount              uint64               `move:"u64"`
}

type ReleasedOrMinted struct {
	RemoteChainSelector uint64               `move:"u64"`
	LocalToken          aptos.AccountAddress `move:"address"`
	Recipient           aptos.AccountAddress `move:"address"`
	Amount              uint64               `move:"u64"`
}

type AllowlistRemove struct {
	Sender aptos.AccountAddress `move:"address"`
}

type AllowlistAdd struct {
	Sender aptos.AccountAddress `move:"address"`
}

type RemotePoolAdded struct {
	RemoteChainSelector uint64 `move:"u64"`
	RemotePoolAddress   []byte `move:"vector<u8>"`
}

type RemotePoolRemoved struct {
	RemoteChainSelector uint64 `move:"u64"`
	RemotePoolAddress   []byte `move:"vector<u8>"`
}

type ChainAdded struct {
	RemoteChainSelector uint64 `move:"u64"`
	RemoteTokenAddress  []byte `move:"vector<u8>"`
}

type ChainRemoved struct {
	RemoteChainSelector uint64 `move:"u64"`
}

type LiquidityAdded struct {
	LocalToken aptos.AccountAddress `move:"address"`
	Provider   aptos.AccountAddress `move:"address"`
	Amount     uint64               `move:"u64"`
}

type LiquidityRemoved struct {
	LocalToken aptos.AccountAddress `move:"address"`
	Provider   aptos.AccountAddress `move:"address"`
	Amount     uint64               `move:"u64"`
}

type RebalancerSet struct {
	OldRebalancer aptos.AccountAddress `move:"address"`
	NewRebalancer aptos.AccountAddress `move:"address"`
}

type TokenPoolContract struct {
	*bind.BoundContract
	tokenPoolEncoder
}

var _ TokenPoolInterface = TokenPoolContract{}

func (c TokenPoolContract) Encoder() TokenPoolEncoder {
	return c.tokenPoolEncoder
}

// View Functions

func (c TokenPoolContract) GetRouter(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := c.tokenPoolEncoder.GetRouter()
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

func (c TokenPoolContract) ParseRemoteDecimals(opts *bind.CallOpts, sourcePoolData []byte, localDecimals byte) (byte, error) {
	module, function, typeTags, args, err := c.tokenPoolEncoder.ParseRemoteDecimals(sourcePoolData, localDecimals)
	if err != nil {
		return *new(byte), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(byte), err
	}

	var (
		r0 byte
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(byte), err
	}
	return r0, nil
}

func (c TokenPoolContract) CalculateLocalAmount(opts *bind.CallOpts, remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (uint64, error) {
	module, function, typeTags, args, err := c.tokenPoolEncoder.CalculateLocalAmount(remoteAmount, remoteDecimals, localDecimals)
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

func (c TokenPoolContract) CalculateLocalAmountInternal(opts *bind.CallOpts, remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (*big.Int, error) {
	module, function, typeTags, args, err := c.tokenPoolEncoder.CalculateLocalAmountInternal(remoteAmount, remoteDecimals, localDecimals)
	if err != nil {
		return *new(*big.Int), err
	}

	callData, err := c.Call(opts, module, function, typeTags, args)
	if err != nil {
		return *new(*big.Int), err
	}

	var (
		r0 *big.Int
	)

	if err := codec.DecodeAptosJsonArray(callData, &r0); err != nil {
		return *new(*big.Int), err
	}
	return r0, nil
}

// Entry Functions

// Encoder
type tokenPoolEncoder struct {
	*bind.BoundContract
}

func (c tokenPoolEncoder) GetRouter() (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("get_router", nil, []string{}, []any{})
}

func (c tokenPoolEncoder) ParseRemoteDecimals(sourcePoolData []byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("parse_remote_decimals", nil, []string{
		"vector<u8>",
		"u8",
	}, []any{
		sourcePoolData,
		localDecimals,
	})
}

func (c tokenPoolEncoder) CalculateLocalAmount(remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_local_amount", nil, []string{
		"u256",
		"u8",
		"u8",
	}, []any{
		remoteAmount,
		remoteDecimals,
		localDecimals,
	})
}

func (c tokenPoolEncoder) CalculateLocalAmountInternal(remoteAmount *big.Int, remoteDecimals byte, localDecimals byte) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("calculate_local_amount_internal", nil, []string{
		"u256",
		"u8",
		"u8",
	}, []any{
		remoteAmount,
		remoteDecimals,
		localDecimals,
	})
}

func (c tokenPoolEncoder) Initialize(localToken aptos.AccountAddress, allowlist []aptos.AccountAddress) (bind.ModuleInformation, string, []aptos.TypeTag, [][]byte, error) {
	return c.BoundContract.Encode("initialize", nil, []string{
		"address",
		"vector<address>",
	}, []any{
		localToken,
		allowlist,
	})
}
