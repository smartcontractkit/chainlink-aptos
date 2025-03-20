package module_mcms_registry

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

type MCMSRegistryInterface interface {
	GetNewCodeObjectOwnerAddress(opts *bind.CallOpts, newOwnerSeed string) (aptos.AccountAddress, error)
	GetNewCodeObjectAddress(opts *bind.CallOpts, newOwnerSeed string) (aptos.AccountAddress, error)
	GetPreexistingCodeObjectOwnerAddress(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	GetRegisteredOwnerAddress(opts *bind.CallOpts, accountAddress aptos.AccountAddress) (aptos.AccountAddress, error)
	IsOwnedCodeObject(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (bool, error)

	CreateOwnerForPreexistingCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
	TransferCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error)
}

var _ MCMSRegistryInterface = MCMSRegistry{}

type MCMSRegistry struct {
	MCMSRegistryCaller
	MCMSRegistryTransactor
}

type MCMSRegistryCaller struct {
	*bind.BoundContract
}

func (m MCMSRegistryCaller) EncodeGetNewCodeObjectOwnerAddress(newOwnerSeed string) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"get_new_code_object_owner_address",
		nil,
		[]string{
			"vector<u8>",
		},
		[]any{
			newOwnerSeed,
		})
}

func (m MCMSRegistryCaller) GetNewCodeObjectOwnerAddress(opts *bind.CallOpts, newOwnerSeed string) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := m.EncodeGetNewCodeObjectOwnerAddress(newOwnerSeed)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var (
		newOwnerAddress aptos.AccountAddress
	)
	if err := codec.DecodeAptosJsonArray(data, &newOwnerAddress); err != nil {
		return aptos.AccountAddress{}, err
	}
	return newOwnerAddress, nil
}

func (m MCMSRegistryCaller) EncodeGetNewCodeObjectAddress(newOwnerSeed string) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"get_new_code_object_address",
		nil,
		[]string{
			"vector<u8>",
		},
		[]any{
			newOwnerSeed,
		})
}

func (m MCMSRegistryCaller) GetNewCodeObjectAddress(opts *bind.CallOpts, newOwnerSeed string) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := m.EncodeGetNewCodeObjectAddress(newOwnerSeed)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var (
		newCodeObjectAddress aptos.AccountAddress
	)
	if err := codec.DecodeAptosJsonArray(data, &newCodeObjectAddress); err != nil {
		return aptos.AccountAddress{}, err
	}
	return newCodeObjectAddress, nil
}

func (m MCMSRegistryCaller) EncodeGetPreexistingCodeObjectOwnerAddress(objectAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"get_preexisting_code_object_owner_address",
		nil,
		[]string{
			"address",
		},
		[]any{
			objectAddress,
		})
}

func (m MCMSRegistryCaller) GetPreexistingCodeObjectOwnerAddress(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := m.EncodeGetPreexistingCodeObjectOwnerAddress(objectAddress)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var (
		ownerAddress aptos.AccountAddress
	)
	if err := codec.DecodeAptosJsonArray(data, &ownerAddress); err != nil {
		return aptos.AccountAddress{}, err
	}
	return ownerAddress, nil
}

func (m MCMSRegistryCaller) EncodeGetRegisteredOwnerAddress(accountAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"get_registered_owner_address",
		nil,
		[]string{
			"address",
		},
		[]any{
			accountAddress,
		})
}

func (m MCMSRegistryCaller) GetRegisteredOwnerAddress(opts *bind.CallOpts, accountAddress aptos.AccountAddress) (aptos.AccountAddress, error) {
	module, function, typeTags, args, err := m.EncodeGetRegisteredOwnerAddress(accountAddress)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}
	var (
		ownerAddress aptos.AccountAddress
	)
	if err := codec.DecodeAptosJsonArray(data, &ownerAddress); err != nil {
		return aptos.AccountAddress{}, err
	}
	return ownerAddress, nil
}

func (m MCMSRegistryCaller) EncodeIsOwnedCodeObject(objectAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"is_owned_code_object",
		nil,
		[]string{
			"address",
		},
		[]any{
			objectAddress,
		})
}

func (m MCMSRegistryCaller) IsOwnedCodeObject(opts *bind.CallOpts, objectAddress aptos.AccountAddress) (bool, error) {
	module, function, typeTags, args, err := m.EncodeIsOwnedCodeObject(objectAddress)
	if err != nil {
		return false, err
	}
	data, err := m.Call(opts, module, function, typeTags, args)
	if err != nil {
		return false, err
	}
	var (
		isOwned bool
	)
	if err := codec.DecodeAptosJsonArray(data, &isOwned); err != nil {
		return false, err
	}
	return isOwned, nil
}

type MCMSRegistryTransactor struct {
	*bind.BoundContract
}

func (m MCMSRegistryTransactor) EncodeCreateOwnerForPreexistingCodeObject(objectAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"create_owner_for_preexisting_code_object",
		nil,
		[]string{
			"address",
		},
		[]any{
			objectAddress,
		})
}

func (m MCMSRegistryTransactor) CreateOwnerForPreexistingCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeCreateOwnerForPreexistingCodeObject(objectAddress)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}

func (m MCMSRegistryTransactor) EncodeTransferCodeObject(objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return m.Encode(
		"transfer_code_object",
		nil,
		[]string{
			"address",
			"address",
		},
		[]any{
			objectAddress,
			newOwnerAddress,
		})
}

func (m MCMSRegistryTransactor) TransferCodeObject(opts *bind.TransactOpts, objectAddress aptos.AccountAddress, newOwnerAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := m.EncodeTransferCodeObject(objectAddress, newOwnerAddress)
	if err != nil {
		return nil, err
	}
	return m.Transact(opts, module, function, typeTags, args)
}
