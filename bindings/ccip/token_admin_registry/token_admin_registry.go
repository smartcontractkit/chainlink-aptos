package module_token_admin_registry

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"
)

type TokenAdminRegistryInterface interface {
	GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error)
	GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error)
	GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error)
	GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error) // TODO check how to handle the Option<> type
	IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error)

	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
	SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error)
	AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error)
}

var _ TokenAdminRegistryInterface = TokenAdminRegistry{}

type TokenAdminRegistry struct {
	TokenAdminRegistryCaller
	TokenAdminRegistryTransactor
}

type TokenAdminRegistryCaller struct {
	*bind.BoundContract
}

func (t TokenAdminRegistryCaller) EncodeGetPools(localTokens []aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("get_pools", nil, []string{"vector<address>"}, []any{localTokens})
}

func (t TokenAdminRegistryCaller) GetPools(opts *bind.CallOpts, localTokens []aptos.AccountAddress) ([]aptos.AccountAddress, error) {
	module, function, typeTags, args, err := t.EncodeGetPools(localTokens)
	if err != nil {
		return nil, err
	}
	data, err := t.Call(opts, module, function, typeTags, args)
	if err != nil {
		return nil, err
	}
	var pools []aptos.AccountAddress
	if err := codec.DecodeAptosJsonArray(data, &pools); err != nil {
		return nil, err
	}
	return pools, nil
}

func (t TokenAdminRegistryCaller) EncodeGetPool(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("get_pool", nil, []string{"address"}, []any{localToken})
}

func (t TokenAdminRegistryCaller) GetPool(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := t.EncodeGetPool(localToken)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	data, err := t.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var pool aptos.AccountAddress
	if err := codec.DecodeAptosJsonArray(data, &pool); err != nil {
		return aptos.AccountAddress{}, err
	}
	return pool, nil
}

func (t TokenAdminRegistryCaller) EncodeGetTokenConfig(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("get_token_config", nil, []string{"address"}, []any{localToken})
}

func (t TokenAdminRegistryCaller) GetTokenConfig(opts *bind.CallOpts, localToken aptos.AccountAddress) (aptos.AccountAddress, aptos.AccountAddress, aptos.AccountAddress, error) {
	module, function, typeTags, args, err := t.EncodeGetTokenConfig(localToken)
	if err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	data, err := t.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	var (
		tokenPoolAddress     aptos.AccountAddress
		administrator        aptos.AccountAddress
		pendingAdministrator aptos.AccountAddress
	)
	if err := codec.DecodeAptosJsonArray(data, &tokenPoolAddress, &administrator, &pendingAdministrator); err != nil {
		return aptos.AccountAddress{}, aptos.AccountAddress{}, aptos.AccountAddress{}, err
	}
	return tokenPoolAddress, administrator, pendingAdministrator, nil
}

func (t TokenAdminRegistryCaller) EncodeGetAllConfiguredTokens(startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("get_all_configured_tokens", nil, []string{"u64", "u64", "u64"}, []any{startingBucketIndex, startingVectorIndex, maxCount})
}

func (t TokenAdminRegistryCaller) GetAllConfiguredTokens(opts *bind.CallOpts, startingBucketIndex uint64, startingVectorIndex uint64, maxCount uint64) ([]aptos.AccountAddress, *uint64, *uint64, error) {
	module, function, typeTags, args, err := t.EncodeGetAllConfiguredTokens(startingBucketIndex, startingVectorIndex, maxCount)
	if err != nil {
		return nil, nil, nil, err
	}
	data, err := t.Call(opts, module, function, typeTags, args)
	if err != nil {
		return nil, nil, nil, err
	}
	var (
		tokens          []aptos.AccountAddress
		nextBucketIndex uint64
		nextVectorIndex uint64
	)
	if err := codec.DecodeAptosJsonArray(data, &tokens, &nextBucketIndex, &nextVectorIndex); err != nil {
		return nil, nil, nil, err
	}
	// TODO Check how to handle the Option<> type
	return tokens, &nextBucketIndex, &nextVectorIndex, nil
}

func (t TokenAdminRegistryCaller) EncodeIsAdministrator(localToken aptos.AccountAddress, administrator aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("is_administrator", nil, []string{"address", "address"}, []any{localToken, administrator})
}

func (t TokenAdminRegistryCaller) IsAdministrator(opts *bind.CallOpts, localToken aptos.AccountAddress, administrator aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := t.EncodeIsAdministrator(localToken, administrator)
	if err != nil {
		return false, err
	}
	data, err := t.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, err
	}
	var result bool
	if err := codec.DecodeAptosJsonArray(data, &result); err != nil {
		return false, err
	}
	return result, nil
}

type TokenAdminRegistryTransactor struct {
	*bind.BoundContract
}

func (t TokenAdminRegistryTransactor) EncodeInitialize(opts *bind.TransactOpts) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("initialize", nil, nil, nil)
}

func (t TokenAdminRegistryTransactor) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := t.EncodeInitialize(opts)
	if err != nil {
		return nil, err
	}
	return t.Transact(opts, module, function, typeTags, args)
}

func (t TokenAdminRegistryTransactor) EncodeSetPool(localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("set_pool", nil, []string{"address", "address"}, []any{localToken, tokenPoolAddress})
}

func (t TokenAdminRegistryTransactor) SetPool(opts *bind.TransactOpts, localToken aptos.AccountAddress, tokenPoolAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := t.EncodeSetPool(localToken, tokenPoolAddress)
	if err != nil {
		return nil, err
	}
	return t.Transact(opts, module, function, typeTags, args)
}

func (t TokenAdminRegistryTransactor) EncodeTransferAdminRole(localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("transfer_admin_role", nil, []string{"address", "address"}, []any{localToken, newAdmin})
}

func (t TokenAdminRegistryTransactor) TransferAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress, newAdmin aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := t.EncodeTransferAdminRole(localToken, newAdmin)
	if err != nil {
		return nil, err
	}
	return t.Transact(opts, module, function, typeTags, args)
}

func (t TokenAdminRegistryTransactor) EncodeAcceptAdminRole(localToken aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return t.Encode("accept_admin_role", nil, []string{"address"}, []any{localToken})
}

func (t TokenAdminRegistryTransactor) AcceptAdminRole(opts *bind.TransactOpts, localToken aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := t.EncodeAcceptAdminRole(localToken)
	if err != nil {
		return nil, err
	}
	return t.Transact(opts, module, function, typeTags, args)
}
