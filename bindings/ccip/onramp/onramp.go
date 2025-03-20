package module_onramp

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

// OnrampInterface defines the interface for interacting with the Onramp contract
type OnrampInterface interface {
	GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error)
	GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error)
	GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (bool, uint64, bool, error)
	GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error)
	GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error)
	GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error)
	GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error)

	Initialize(opts *bind.TransactOpts, chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error)
	SetDynamicConfig(opts *bind.TransactOpts, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error)
	ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error)
}

// Structs
type StaticConfig struct {
	ChainSelector uint64
}

type DynamicConfig struct {
	AllowlistAdmin aptos.AccountAddress
}

var _ OnrampInterface = Onramp{}

type Onramp struct {
	OnrampCaller
	OnrampTransactor
}

type OnrampCaller struct {
	*bind.BoundContract
}

func (o OnrampCaller) EncodeGetExpectedNextSequenceNumber(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_expected_next_sequence_number", nil, []string{"u64"}, []any{destChainSelector})
}

func (o OnrampCaller) GetExpectedNextSequenceNumber(opts *bind.CallOpts, destChainSelector uint64) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetExpectedNextSequenceNumber(destChainSelector)
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var sequence uint64
	if err := codec.DecodeAptosJsonArray(data, &sequence); err != nil {
		return 0, err
	}
	return sequence, nil
}

func (o OnrampCaller) EncodeGetFee(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_fee", nil, []string{
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

func (o OnrampCaller) GetFee(opts *bind.CallOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetFee(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return 0, err
	}

	callData, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var fee uint64
	if err := codec.DecodeAptosJsonArray(callData, &fee); err != nil {
		return 0, err
	}
	return fee, nil
}

func (o OnrampCaller) EncodeGetDestChainConfig(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_dest_chain_config", nil, []string{"u64"}, []any{destChainSelector})
}

func (o OnrampCaller) GetDestChainConfig(opts *bind.CallOpts, destChainSelector uint64) (bool, uint64, bool, error) {
	module, function, typeTags, args, err := o.EncodeGetDestChainConfig(destChainSelector)
	if err != nil {
		return false, 0, false, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, 0, false, err
	}

	var isEnabled bool
	var sequenceNumber uint64
	var allowlistEnabled bool

	if err := codec.DecodeAptosJsonArray(data, &isEnabled, &sequenceNumber, &allowlistEnabled); err != nil {
		return false, 0, false, err
	}
	return isEnabled, sequenceNumber, allowlistEnabled, nil
}

func (o OnrampCaller) EncodeGetAllowedSendersList(destChainSelector uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_allowed_senders_list", nil, []string{"u64"}, []any{destChainSelector})
}

func (o OnrampCaller) GetAllowedSendersList(opts *bind.CallOpts, destChainSelector uint64) (bool, []aptos.AccountAddress, error) {
	module, function, typeTags, args, err := o.EncodeGetAllowedSendersList(destChainSelector)
	if err != nil {
		return false, nil, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, nil, err
	}

	var allowlistEnabled bool
	var allowedSenders []aptos.AccountAddress

	if err := codec.DecodeAptosJsonArray(data, &allowlistEnabled, &allowedSenders); err != nil {
		return false, nil, err
	}
	return allowlistEnabled, allowedSenders, nil
}

func (o OnrampCaller) EncodeGetOutboundNonce(destChainSelector uint64, sender aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_outbound_nonce", nil, []string{"u64", "address"}, []any{destChainSelector, sender})
}

func (o OnrampCaller) GetOutboundNonce(opts *bind.CallOpts, destChainSelector uint64, sender aptos.AccountAddress) (uint64, error) {
	module, function, typeTags, args, err := o.EncodeGetOutboundNonce(destChainSelector, sender)
	if err != nil {
		return 0, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var nonce uint64
	if err := codec.DecodeAptosJsonArray(data, &nonce); err != nil {
		return 0, err
	}
	return nonce, nil
}

func (o OnrampCaller) EncodeGetStaticConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_static_config", nil, nil, nil)
}

func (o OnrampCaller) GetStaticConfig(opts *bind.CallOpts) (StaticConfig, error) {
	module, function, typeTags, args, err := o.EncodeGetStaticConfig()
	if err != nil {
		return StaticConfig{}, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return StaticConfig{}, err
	}

	var config StaticConfig
	if err := codec.DecodeAptosJsonArray(data, &config); err != nil {
		return StaticConfig{}, err
	}
	return config, nil
}

func (o OnrampCaller) EncodeGetDynamicConfig() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("get_dynamic_config", nil, nil, nil)
}

func (o OnrampCaller) GetDynamicConfig(opts *bind.CallOpts) (DynamicConfig, error) {
	module, function, typeTags, args, err := o.EncodeGetDynamicConfig()
	if err != nil {
		return DynamicConfig{}, err
	}

	data, err := o.Call(opts, module, function, typeTags, args)
	if err != nil {
		return DynamicConfig{}, err
	}

	var config DynamicConfig
	if err := codec.DecodeAptosJsonArray(data, &config); err != nil {
		return DynamicConfig{}, err
	}
	return config, nil
}

type OnrampTransactor struct {
	*bind.BoundContract
}

func (o OnrampTransactor) EncodeInitialize(chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("initialize", nil, []string{"u64", "address", "vector<u64>", "vector<bool>", "vector<bool>"}, []any{
		chainSelector,
		allowlistAdmin,
		destChainSelectors,
		destChainEnabled,
		destChainAllowlistEnabled,
	})
}

func (o OnrampTransactor) Initialize(opts *bind.TransactOpts, chainSelector uint64, allowlistAdmin aptos.AccountAddress, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeInitialize(chainSelector, allowlistAdmin, destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OnrampTransactor) EncodeCCIPSend(destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("ccip_send", nil, []string{"u64", "vector<u8>", "vector<u8>", "vector<address>", "vector<u64>", "vector<address>", "address", "address", "vector<u8>"}, []any{
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

func (o OnrampTransactor) CCIPSend(opts *bind.TransactOpts, destChainSelector uint64, receiver []byte, data []byte, tokenAddresses []aptos.AccountAddress, tokenAmounts []uint64, tokenStoreAddresses []aptos.AccountAddress, feeToken aptos.AccountAddress, feeTokenStore aptos.AccountAddress, extraArgs []byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeCCIPSend(destChainSelector, receiver, data, tokenAddresses, tokenAmounts, tokenStoreAddresses, feeToken, feeTokenStore, extraArgs)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OnrampTransactor) EncodeSetDynamicConfig(allowlistAdmin aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("set_dynamic_config", nil, []string{"address"}, []any{allowlistAdmin})
}

func (o OnrampTransactor) SetDynamicConfig(opts *bind.TransactOpts, allowlistAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeSetDynamicConfig(allowlistAdmin)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OnrampTransactor) EncodeApplyDestChainConfigUpdates(destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("apply_dest_chain_config_updates", nil, []string{"vector<u64>", "vector<bool>", "vector<bool>"}, []any{
		destChainSelectors,
		destChainEnabled,
		destChainAllowlistEnabled,
	})
}

func (o OnrampTransactor) ApplyDestChainConfigUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainEnabled []bool, destChainAllowlistEnabled []bool) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeApplyDestChainConfigUpdates(destChainSelectors, destChainEnabled, destChainAllowlistEnabled)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}

func (o OnrampTransactor) EncodeApplyAllowlistUpdates(destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return o.Encode("apply_allowlist_updates", nil, []string{"vector<u64>", "vector<bool>", "vector<vector<address>>", "vector<vector<address>>"}, []any{
		destChainSelectors,
		destChainAllowlistEnabled,
		destChainAddAllowedSenders,
		destChainRemoveAllowedSenders,
	})
}

func (o OnrampTransactor) ApplyAllowlistUpdates(opts *bind.TransactOpts, destChainSelectors []uint64, destChainAllowlistEnabled []bool, destChainAddAllowedSenders [][]aptos.AccountAddress, destChainRemoveAllowedSenders [][]aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := o.EncodeApplyAllowlistUpdates(destChainSelectors, destChainAllowlistEnabled, destChainAddAllowedSenders, destChainRemoveAllowedSenders)
	if err != nil {
		return nil, err
	}
	return o.Transact(opts, module, function, typeTags, args)
}
