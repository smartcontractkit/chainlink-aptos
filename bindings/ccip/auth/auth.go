package module_auth

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
)

// AuthInterface defines the interface for interacting with the Auth contract
type AuthInterface interface {
	Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error)
}

var _ AuthInterface = Auth{}

type Auth struct {
	AuthCaller
	AuthTransactor
}

type AuthCaller struct {
	*bind.BoundContract
}

type AuthTransactor struct {
	*bind.BoundContract
}

func (r AuthTransactor) EncodeInitialize() (aptos.ModuleId, string, []aptos.TypeTag, [][]byte, error) {
	return r.Encode("initialize", nil, nil, nil)
}

func (r AuthTransactor) Initialize(opts *bind.TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := r.EncodeInitialize()
	if err != nil {
		return nil, err
	}
	return r.Transact(opts, module, function, typeTags, args)
}
