package ccip

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/bind"
	module_auth "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/auth"
	module_fee_quoter "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/fee_quoter"
	module_offramp "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/offramp"
	module_onramp "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/onramp"
	module_receiver_registry "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/receiver_registry"
	module_rmn_remote "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/rmn_remote"
	module_token_admin_registry "github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-internal-integrations/aptos/bindings/compile"
)

type CCIP struct {
	Address aptos.AccountAddress

	Auth               module_auth.Auth
	FeeQuoter          module_fee_quoter.FeeQuoter
	Offramp            module_offramp.Offramp
	Onramp             module_onramp.Onramp
	ReceiverRegistry   module_receiver_registry.ReceiverRegistry
	RMNRemote          module_rmn_remote.RMNRemote
	TokenAdminRegistry module_token_admin_registry.TokenAdminRegistry
}

const (
	DefaultSeed = "chainlink_ccip"
)

func Compile(address aptos.AccountAddress) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip": address,
	}
	// Compile using CLI
	return compile.CompilePackage("ccip", namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIP {
	authContract := bind.NewBoundContract(address, "auth", client)
	feeQuoterContract := bind.NewBoundContract(address, "fee_quoter", client)
	offrampContract := bind.NewBoundContract(address, "offramp", client)
	onrampContract := bind.NewBoundContract(address, "onramp", client)
	receiverRegistryContract := bind.NewBoundContract(address, "receiver_registry", client)
	rmnRemoteContract := bind.NewBoundContract(address, "rmn_remote", client)
	tokenAdminRegistryContract := bind.NewBoundContract(address, "token_admin_registry", client)
	return CCIP{
		Address: address,
		Auth: module_auth.Auth{
			AuthCaller:     module_auth.AuthCaller{BoundContract: authContract},
			AuthTransactor: module_auth.AuthTransactor{BoundContract: authContract},
		},
		FeeQuoter: module_fee_quoter.FeeQuoter{
			FeeQuoterCaller:     module_fee_quoter.FeeQuoterCaller{BoundContract: feeQuoterContract},
			FeeQuoterTransactor: module_fee_quoter.FeeQuoterTransactor{BoundContract: feeQuoterContract},
		},
		Offramp: module_offramp.Offramp{
			OfframpCaller:     module_offramp.OfframpCaller{BoundContract: offrampContract},
			OfframpTransactor: module_offramp.OfframpTransactor{BoundContract: offrampContract},
		},
		Onramp: module_onramp.Onramp{
			OnrampCaller:     module_onramp.OnrampCaller{BoundContract: onrampContract},
			OnrampTransactor: module_onramp.OnrampTransactor{BoundContract: onrampContract},
		},
		ReceiverRegistry: module_receiver_registry.ReceiverRegistry{
			ReceiverRegistryCaller:     module_receiver_registry.ReceiverRegistryCaller{BoundContract: receiverRegistryContract},
			ReceiverRegistryTransactor: module_receiver_registry.ReceiverRegistryTransactor{BoundContract: receiverRegistryContract},
		},
		RMNRemote: module_rmn_remote.RMNRemote{
			RMNRemoteCaller:     module_rmn_remote.RMNRemoteCaller{BoundContract: rmnRemoteContract},
			RMNRemoteTransactor: module_rmn_remote.RMNRemoteTransactor{BoundContract: rmnRemoteContract},
		},
		TokenAdminRegistry: module_token_admin_registry.TokenAdminRegistry{
			TokenAdminRegistryCaller:     module_token_admin_registry.TokenAdminRegistryCaller{BoundContract: tokenAdminRegistryContract},
			TokenAdminRegistryTransactor: module_token_admin_registry.TokenAdminRegistryTransactor{BoundContract: tokenAdminRegistryContract},
		},
	}
}

// DeployToObject deploys the CCIP contract to a new named object.
// The resulting address will be calculated using the deployer's account address and the next sequence number
// This should not be used in production, where CCIP is deployed via MCMS.
func DeployToObject(
	auth aptos.TransactionSigner,
	client *aptos.NodeClient,
) (aptos.AccountAddress, *api.PendingTransaction, CCIP, error) {
	address, tx, err := bind.DeployPackageToObject(auth, client, "ccip", nil)
	if err != nil {
		return aptos.AccountAddress{}, nil, CCIP{}, err
	}
	return address, tx, Bind(address, client), nil
}
