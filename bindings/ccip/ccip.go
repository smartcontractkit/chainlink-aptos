package ccip

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_auth "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/auth"
	module_fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	module_offramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/offramp"
	module_onramp "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/onramp"
	module_receiver_registry "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/receiver_registry"
	module_rmn_remote "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/rmn_remote"
	module_token_admin_registry "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

type CCIP interface {
	Address() aptos.AccountAddress

	Auth() module_auth.Auth
	FeeQuoter() module_fee_quoter.FeeQuoter
	Offramp() module_offramp.Offramp
	Onramp() module_onramp.Onramp
	ReceiverRegistry() module_receiver_registry.ReceiverRegistry
	RMNRemote() module_rmn_remote.RMNRemote
	TokenAdminRegistry() module_token_admin_registry.TokenAdminRegistry
}

var _ CCIP = CCIPContract{}

type CCIPContract struct {
	address aptos.AccountAddress

	auth               module_auth.Auth
	feeQuoter          module_fee_quoter.FeeQuoter
	offramp            module_offramp.Offramp
	onramp             module_onramp.Onramp
	receiverRegistry   module_receiver_registry.ReceiverRegistry
	rmnRemote          module_rmn_remote.RMNRemote
	tokenAdminRegistry module_token_admin_registry.TokenAdminRegistry
}

func (C CCIPContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPContract) Auth() module_auth.Auth {
	return C.auth
}

func (C CCIPContract) FeeQuoter() module_fee_quoter.FeeQuoter {
	return C.feeQuoter
}

func (C CCIPContract) Offramp() module_offramp.Offramp {
	return C.offramp
}

func (C CCIPContract) Onramp() module_onramp.Onramp {
	return C.onramp
}

func (C CCIPContract) ReceiverRegistry() module_receiver_registry.ReceiverRegistry {
	return C.receiverRegistry
}

func (C CCIPContract) RMNRemote() module_rmn_remote.RMNRemote {
	return C.rmnRemote
}

func (C CCIPContract) TokenAdminRegistry() module_token_admin_registry.TokenAdminRegistry {
	return C.tokenAdminRegistry
}

const (
	DefaultSeed = "chainlink_ccip"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_auth.FunctionInfo,
	module_fee_quoter.FunctionInfo,
	module_offramp.FunctionInfo,
	module_onramp.FunctionInfo,
	module_receiver_registry.FunctionInfo,
	module_rmn_remote.FunctionInfo,
	module_token_admin_registry.FunctionInfo,
)

func Compile(address aptos.AccountAddress, mcmsAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      address,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = address
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
	return CCIPContract{
		address: address,
		auth: module_auth.AuthContract{
			AuthCaller:     module_auth.AuthCaller{BoundContract: authContract},
			AuthTransactor: module_auth.AuthTransactor{BoundContract: authContract},
		},
		feeQuoter: module_fee_quoter.FeeQuoterContract{
			FeeQuoterCaller:     module_fee_quoter.FeeQuoterCaller{BoundContract: feeQuoterContract},
			FeeQuoterTransactor: module_fee_quoter.FeeQuoterTransactor{BoundContract: feeQuoterContract},
		},
		offramp: module_offramp.OfframpContract{
			OfframpCaller:     module_offramp.OfframpCaller{BoundContract: offrampContract},
			OfframpTransactor: module_offramp.OfframpTransactor{BoundContract: offrampContract},
		},
		onramp: module_onramp.OnrampContract{
			OnrampCaller:     module_onramp.OnrampCaller{BoundContract: onrampContract},
			OnrampTransactor: module_onramp.OnrampTransactor{BoundContract: onrampContract},
		},
		receiverRegistry: module_receiver_registry.ReceiverRegistryContract{
			ReceiverRegistryCaller:     module_receiver_registry.ReceiverRegistryCaller{BoundContract: receiverRegistryContract},
			ReceiverRegistryTransactor: module_receiver_registry.ReceiverRegistryTransactor{BoundContract: receiverRegistryContract},
		},
		rmnRemote: module_rmn_remote.RMNRemoteContract{
			RMNRemoteCaller:     module_rmn_remote.RMNRemoteCaller{BoundContract: rmnRemoteContract},
			RMNRemoteTransactor: module_rmn_remote.RMNRemoteTransactor{BoundContract: rmnRemoteContract},
		},
		tokenAdminRegistry: module_token_admin_registry.TokenAdminRegistryContract{
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
	client aptos.AptosRpcClient,
	mcmsAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (aptos.AccountAddress, *api.PendingTransaction, CCIP, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = mcmsAddress
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, "ccip", namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, CCIPContract{}, err
	}
	return address, tx, Bind(address, client), nil
}
