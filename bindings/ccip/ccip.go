package ccip

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_auth "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/auth"
	module_fee_quoter "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/fee_quoter"
	module_nonce_manager "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/nonce_manager"
	module_receiver_registry "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/receiver_registry"
	module_rmn_remote "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/rmn_remote"
	module_token_admin_registry "github.com/smartcontractkit/chainlink-aptos/bindings/ccip/token_admin_registry"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type CCIP interface {
	Address() aptos.AccountAddress

	Auth() module_auth.AuthInterface
	FeeQuoter() module_fee_quoter.FeeQuoterInterface
	NonceManager() module_nonce_manager.NonceManagerInterface
	ReceiverRegistry() module_receiver_registry.ReceiverRegistryInterface
	RMNRemote() module_rmn_remote.RMNRemoteInterface
	TokenAdminRegistry() module_token_admin_registry.TokenAdminRegistryInterface
}

var _ CCIP = CCIPContract{}

type CCIPContract struct {
	address aptos.AccountAddress

	auth               module_auth.AuthInterface
	feeQuoter          module_fee_quoter.FeeQuoterInterface
	nonceManager       module_nonce_manager.NonceManagerInterface
	receiverRegistry   module_receiver_registry.ReceiverRegistryInterface
	rmnRemote          module_rmn_remote.RMNRemoteInterface
	tokenAdminRegistry module_token_admin_registry.TokenAdminRegistryInterface
}

func (C CCIPContract) Address() aptos.AccountAddress {
	return C.address
}

func (C CCIPContract) Auth() module_auth.AuthInterface {
	return C.auth
}

func (C CCIPContract) FeeQuoter() module_fee_quoter.FeeQuoterInterface {
	return C.feeQuoter
}

func (C CCIPContract) NonceManager() module_nonce_manager.NonceManagerInterface {
	return C.nonceManager
}

func (C CCIPContract) ReceiverRegistry() module_receiver_registry.ReceiverRegistryInterface {
	return C.receiverRegistry
}

func (C CCIPContract) RMNRemote() module_rmn_remote.RMNRemoteInterface {
	return C.rmnRemote
}

func (C CCIPContract) TokenAdminRegistry() module_token_admin_registry.TokenAdminRegistryInterface {
	return C.tokenAdminRegistry
}

const (
	DefaultSeed = "chainlink_ccip"
)

var FunctionInfo = bind.MustParseFunctionInfo(
	module_auth.FunctionInfo,
	module_fee_quoter.FunctionInfo,
	module_nonce_manager.FunctionInfo,
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
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIP, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) CCIP {
	return CCIPContract{
		address:            address,
		auth:               module_auth.NewAuth(address, client),
		feeQuoter:          module_fee_quoter.NewFeeQuoter(address, client),
		nonceManager:       module_nonce_manager.NewNonceManager(address, client),
		receiverRegistry:   module_receiver_registry.NewReceiverRegistry(address, client),
		rmnRemote:          module_rmn_remote.NewRMNRemote(address, client),
		tokenAdminRegistry: module_token_admin_registry.NewTokenAdminRegistry(address, client),
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
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIP, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, CCIPContract{}, err
	}
	return address, tx, Bind(address, client), nil
}
