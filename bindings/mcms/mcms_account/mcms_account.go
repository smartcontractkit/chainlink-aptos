package module_mcms_account

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/codec"
)

type MCMSAccountInterface interface {
	Owner(opts *bind.CallOpts) (aptos.AccountAddress, error)
	IsSelfOwned(opts *bind.CallOpts) (bool, error)

	TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferOwnershipToSelf(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

var _ MCMSAccountInterface = MCMSAccount{}

type MCMSAccount struct {
	MCMSAccountCaller
	MCMSAccountTransactor
}

type MCMSAccountCaller struct {
	*bind.BoundContract
}

func (m MCMSAccountCaller) EncodeOwner() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("owner", nil, nil, nil)
}

func (m MCMSAccountCaller) Owner(opts *bind.CallOpts) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := m.EncodeOwner()
	if err != nil {
		return aptos.AccountAddress{}, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}

	var (
		owner aptos.AccountAddress
	)

	if err := codec.DecodeAptosJsonArray(data, &owner); err != nil {
		return aptos.AccountAddress{}, err
	}

	return owner, nil
}

func (m MCMSAccountCaller) EncodeIsSelfOwned() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("is_self_owned", nil, nil, nil)
}

func (m MCMSAccountCaller) IsSelfOwned(opts *bind.CallOpts) (bool, error) {
	module, function, typeTags, args, err := m.EncodeIsSelfOwned()
	if err != nil {
		return false, err
	}

	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, err
	}

	var (
		isSelfOwned bool
	)

	if err := codec.DecodeAptosJsonArray(data, &isSelfOwned); err != nil {
		return false, err
	}

	return isSelfOwned, nil
}

type MCMSAccountTransactor struct {
	*bind.BoundContract
}

func (m MCMSAccountTransactor) EncodeTransferOwnership(
	to aptos.AccountAddress,
) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"transfer_ownership",
		nil,
		[]string{
			"address",
		},
		[]any{
			to,
		})
}

func (m MCMSAccountTransactor) TransferOwnership(opts *bind.TransactOpts, to aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeTransferOwnership(to)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSAccountTransactor) EncodeTransferOwnershipToSelf() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("transfer_ownership_to_self", nil, nil, nil)
}

func (m MCMSAccountTransactor) TransferOwnershipToSelf(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeTransferOwnershipToSelf()
	if err != nil {
		return nil, err
	}

	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSAccountTransactor) EncodeAcceptOwnership() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode("accept_ownership", nil, nil, nil)
}
