package module_receiver_registry

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
)

// ReceiverRegistryInterface defines the interface for interacting with the ReceiverRegistry contract
type ReceiverRegistryInterface interface {
	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

var _ ReceiverRegistryInterface = ReceiverRegistry{}

type ReceiverRegistry struct {
	ReceiverRegistryCaller
	ReceiverRegistryTransactor
}

type ReceiverRegistryCaller struct {
	*bind.BoundContract
}

type ReceiverRegistryTransactor struct {
	*bind.BoundContract
}

func (r ReceiverRegistryTransactor) EncodeInitialize() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("initialize", nil, nil, nil)
}

func (r ReceiverRegistryTransactor) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeInitialize()
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}
