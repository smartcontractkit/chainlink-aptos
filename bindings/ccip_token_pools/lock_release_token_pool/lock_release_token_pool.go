package lock_release_token_pool

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	module_lock_release_token_pool "github.com/smartcontractkit/chainlink-aptos/bindings/ccip_token_pools/lock_release_token_pool/lock_release_token_pool"
	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

type LockReleaseTokenPool interface {
	Address() aptos.AccountAddress

	LockReleaseTokenPool() module_lock_release_token_pool.LockReleaseTokenPoolInterface
}

var _ LockReleaseTokenPool = LockReleaseTokenPoolContract{}

type LockReleaseTokenPoolContract struct {
	address aptos.AccountAddress

	lockReleaseTokenPool module_lock_release_token_pool.LockReleaseTokenPoolInterface
}

func (c LockReleaseTokenPoolContract) Address() aptos.AccountAddress {
	return c.address
}

func (c LockReleaseTokenPoolContract) LockReleaseTokenPool() module_lock_release_token_pool.LockReleaseTokenPoolInterface {
	return c.lockReleaseTokenPool
}

var FunctionInfo = bind.MustParseFunctionInfo(
	module_lock_release_token_pool.FunctionInfo,
)

func Compile(address, ccipAddress, mcmsAddress, ccipTokenPoolAddress, localTokenAddress aptos.AccountAddress, registerMCMSEntrypoints bool) (compile.CompiledPackage, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"lock_release_token_pool":   address,
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"lock_release_local_token":  localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	// Compile using CLI
	return compile.CompilePackage(contracts.CCIPLockReleasePool, namedAddresses)
}

func Bind(address aptos.AccountAddress, client aptos.AptosRpcClient) LockReleaseTokenPool {
	return LockReleaseTokenPoolContract{
		address:              address,
		lockReleaseTokenPool: module_lock_release_token_pool.NewLockReleaseTokenPool(address, client),
	}
}

// DeployToObject deploys the LockReleaseTokenPool to a new named object.
// The token pool's administrator will be set to the deployer's account address.
func DeployToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (aptos.AccountAddress, *api.PendingTransaction, LockReleaseTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"lock_release_local_token":  localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	address, tx, err := bind.DeployPackageToObject(auth, client, contracts.CCIPLockReleasePool, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, nil, err
	}
	return address, tx, Bind(address, client), nil
}

func DeployToExistingObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	ccipAddress,
	mcmsAddress,
	ccipTokenPoolAddress,
	localTokenAddress aptos.AccountAddress,
	registerMCMSEntrypoints bool,
) (*api.PendingTransaction, LockReleaseTokenPool, error) {
	namedAddresses := map[string]aptos.AccountAddress{
		"ccip":                      ccipAddress,
		"ccip_token_pool":           ccipTokenPoolAddress,
		"lock_release_local_token":  localTokenAddress,
		"mcms":                      mcmsAddress,
		"mcms_register_entrypoints": aptos.AccountZero,
	}
	if registerMCMSEntrypoints {
		namedAddresses["mcms_register_entrypoints"] = aptos.AccountOne
	}
	tx, err := bind.UpgradePackageToObject(auth, client, contracts.CCIPLockReleasePool, namedAddresses, ccipTokenPoolAddress)
	if err != nil {
		return nil, nil, err
	}
	return tx, Bind(ccipTokenPoolAddress, client), nil
}
