package bind

import (
	"fmt"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"

	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
	"github.com/smartcontractkit/chainlink-aptos/contracts"
)

const (
	// ChunkSizeInBytes is the default maximum size of a chunk in bytes
	// 55k is the value used in aptos-core. We're using 30k to leave some room as deployments
	// will be done via mcms proposals
	// https://github.com/aptos-labs/aptos-core/blob/e0002dd4ca29d1b65fe10c555ac730a773a54b2f/aptos-move/framework/src/chunked_publish.rs#L13-L13
	ChunkSizeInBytes = 30_000

	// DefaultDeployMaxGasAmount is the default max gas for package deployment transactions.
	// The SDK default (100_000) is too low for deploying Move packages which involve
	// resource account creation + code publishing. Unused gas is not charged on Aptos.
	DefaultDeployMaxGasAmount = uint64(2_000_000)
)

// withDefaultDeployGas prepends DefaultDeployMaxGasAmount to options if no
// MaxGasAmount is already present, so callers can override the default.
func withDefaultDeployGas(options []any) []any {
	for _, opt := range options {
		if _, ok := opt.(aptos.MaxGasAmount); ok {
			return options
		}
	}
	return append([]any{aptos.MaxGasAmount(DefaultDeployMaxGasAmount)}, options...)
}

// extractMaxGasAmount finds a MaxGasAmount in options and returns it as *uint64.
func extractMaxGasAmount(options []any) *uint64 {
	for _, opt := range options {
		if v, ok := opt.(aptos.MaxGasAmount); ok {
			u := uint64(v)
			return &u
		}
	}
	return nil
}

// DeployPackageToObject deploys a package to a new named object address
// The package will be compiled using the CLI and then deployed using 0x1::object_code_deployment::publish
// If the package is too large to be deployed in one go, it will be chunked and deployed using the LargePackages contract
// The resulting address will be calculated using the deployer's account address and the next sequence number,
// following the Aptos NamedObjectScheme
func DeployPackageToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	// The name of the package to deploy
	packageName contracts.Package,
	// Additional named addresses, doesn't have to include the objectAddress
	namedAddresses map[string]aptos.AccountAddress,
	// Optional Aptos SDK transaction options (e.g. aptos.MaxGasAmount).
	// A DefaultDeployMaxGasAmount is applied when no MaxGasAmount is provided.
	options ...any,
) (aptos.AccountAddress, *api.PendingTransaction, error) {
	// Well start by assuming that the package is small enough to be deployed in one go

	// Calculate next named addresses
	address, err := nextObjectCodeDeploymentAddressForAccount(client, auth.AccountAddress(), 0)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	if namedAddresses == nil {
		namedAddresses = make(map[string]aptos.AccountAddress)
	}
	namedAddresses[string(packageName)] = address

	// Compile using CLI
	output, err := compile.CompilePackage(packageName, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}

	chunks, err := CreateChunks(output, ChunkSizeInBytes)
	if err != nil {
		return aptos.AccountAddress{}, nil, fmt.Errorf("failed to create chunks: %w", err)
	}

	if len(chunks) == 1 {
		// No need to chunk, deploy in one go and return
		tx, err := objectCodeDeploymentPublish(auth, client, output, options...)
		if err != nil {
			return aptos.AccountAddress{}, nil, err
		}
		return address, tx, nil
	}

	// Chunking is needed

	// Deploy (or bind, depending on the network) the LargePackages contract
	// TODO this should only be done once
	lpAddress, tx, lp, err := DeployOrBindLargePackages(auth, client)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	if tx != nil {
		// tx will be nil if the contract has already been deployed
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	transactOpts := &TransactOpts{
		Signer:       auth,
		MaxGasAmount: extractMaxGasAmount(withDefaultDeployGas(options)),
	}

	// Check if staging area is empty and clear if it isn't
	if _, err := client.AccountResource(auth.AccountAddress(), fmt.Sprintf("%s::large_packages::StagingArea", lpAddress.String())); err == nil {
		// if there is no error that means the staging area is not empty
		tx, err = lp.CleanupStagingArea(transactOpts)
		if err != nil {
			return aptos.AccountAddress{}, nil, fmt.Errorf("failed to clean up staging area: %w", err)
		}
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	// As this will result in multiple transactions, which will in turn change the sequence number of the deployer account
	// re-calculate the address and recompile with the new address
	address, err = nextObjectCodeDeploymentAddressForAccount(client, auth.AccountAddress(), uint64(len(chunks))-1)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	namedAddresses[string(packageName)] = address
	output, err = compile.CompilePackage(packageName, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	chunks, err = CreateChunks(output, ChunkSizeInBytes)
	if err != nil {
		return aptos.AccountAddress{}, nil, fmt.Errorf("failed to create chunks: %w", err)
	}

	for i := range len(chunks) - 1 {
		tx, err = lp.StageCodeChunk(transactOpts, chunks[i].Metadata, chunks[i].CodeIndices, chunks[i].Chunks)
		if err != nil {
			return aptos.AccountAddress{}, nil, err
		}
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	// The last chunk will actually publish the object code
	tx, err = lp.StageCodeChunkAndPublishToObject(transactOpts, chunks[len(chunks)-1].Metadata, chunks[len(chunks)-1].CodeIndices, chunks[len(chunks)-1].Chunks)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	return address, tx, nil
}

// UpgradePackageToObject upgrades a package or deploys a new package onto an existing code object.
// The package will be compiled using the CLI and then deployed using 0x1::object_code_deployment::upgrade.
// If the package is too large to be deployed in a single transaction or if the force large packages flag
// is set, it will be chunked and deployed using the LargePackages contract.
func UpgradePackageToObject(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	// The name of the package to deploy
	packageName contracts.Package,
	// Additional named addresses, doesn't have to include the objectAddress
	namedAddresses map[string]aptos.AccountAddress,
	objectAddress aptos.AccountAddress,
	// Optional Aptos SDK transaction options (e.g. aptos.MaxGasAmount).
	// A DefaultDeployMaxGasAmount is applied when no MaxGasAmount is provided.
	options ...any,
) (*api.PendingTransaction, error) {
	if namedAddresses == nil {
		namedAddresses = make(map[string]aptos.AccountAddress)
	}
	namedAddresses[string(packageName)] = objectAddress

	// Compile using CLI
	output, err := compile.CompilePackage(packageName, namedAddresses)
	if err != nil {
		return nil, err
	}

	chunks, err := CreateChunks(output, ChunkSizeInBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create chunks: %w", err)
	}

	if len(chunks) == 1 {
		// No need to chunk, deploy in one go and return
		tx, err := objectCodeDeploymentUpgrade(auth, client, output, objectAddress, options...)
		if err != nil {
			return nil, err
		}
		return tx, nil
	}

	// Chunking is needed

	// Deploy (or bind, depending on the network) the LargePackages contract
	// TODO this should only be done once
	lpAddress, tx, lp, err := DeployOrBindLargePackages(auth, client)
	if err != nil {
		return nil, err
	}
	if tx != nil {
		// tx will be nil if the contract has already been deployed
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	transactOpts := &TransactOpts{
		Signer:       auth,
		MaxGasAmount: extractMaxGasAmount(withDefaultDeployGas(options)),
	}

	// Check if staging area is empty and clear if it isn't
	if _, err := client.AccountResource(auth.AccountAddress(), fmt.Sprintf("%s::large_packages::StagingArea", lpAddress.String())); err == nil {
		// if there is no error that means the staging area is not empty
		tx, err = lp.CleanupStagingArea(transactOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to clean up staging area: %w", err)
		}
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	for i := range len(chunks) - 1 {
		tx, err = lp.StageCodeChunk(transactOpts, chunks[i].Metadata, chunks[i].CodeIndices, chunks[i].Chunks)
		if err != nil {
			return nil, err
		}
		_, _ = client.WaitForTransaction(tx.Hash)
	}

	// The last chunk will actually publish the object code
	tx, err = lp.StageCodeChunkAndUpgradeObjectCode(transactOpts, chunks[len(chunks)-1].Metadata, chunks[len(chunks)-1].CodeIndices, chunks[len(chunks)-1].Chunks, objectAddress)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

// DeployPackageToResourceAccount deploys a package to a new resource account
// The package will be compiled using the CLI and then deployed using 0x1::resource_account::create_resource_account_and_publish_package
// The resulting address will be calculated using the deployer's account address and the given seed,
// following the Aptos ResourceAccountScheme
func DeployPackageToResourceAccount(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
	// The name of the package to deploy
	packageName contracts.Package,
	// The seed for the created resource account
	seed string,
	// Additional named addresses, doesn't have to include the address of the resource account
	namedAddresses map[string]aptos.AccountAddress,
	// Optional Aptos SDK transaction options (e.g. aptos.MaxGasAmount).
	// A DefaultDeployMaxGasAmount is applied when no MaxGasAmount is provided.
	options ...any,
) (aptos.AccountAddress, *api.PendingTransaction, error) {
	// Calculate next ResourceAccount address for the deployer
	deployerAddress := auth.AccountAddress()
	resourceAccount := deployerAddress.ResourceAccount([]byte(seed))
	if namedAddresses == nil {
		namedAddresses = make(map[string]aptos.AccountAddress)
	}
	namedAddresses[string(packageName)] = resourceAccount

	// Compile using CLI
	output, err := compile.CompilePackage(packageName, namedAddresses)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}

	tx, err := createResourceAccountAndPublishPackage(auth, client, seed, output, options...)
	if err != nil {
		return aptos.AccountAddress{}, nil, err
	}
	return resourceAccount, tx, nil
}

// calculateNextObjectCodeDeploymentAddress calculates the address of the next named object that will be created
// when performing an object code deployment using 0x1::object_code_deployment::publish
// It uses 0x1::object::create_named_object with the seed being the sending addresses next sequence + a fixed domain separator
func calculateNextObjectCodeDeploymentAddress(address aptos.AccountAddress, currSeq uint64) aptos.AccountAddress {
	sequenceBytes, _ := bcs.SerializeU64(currSeq + 1)
	domainSeparatorBytes, _ := bcs.SerializeBytes([]byte("aptos_framework::object_code_deployment"))
	seedBytes := append(domainSeparatorBytes, sequenceBytes...)

	return address.NamedObjectAddress(seedBytes)
}

func nextObjectCodeDeploymentAddressForAccount(client aptos.AptosRpcClient, account aptos.AccountAddress, offset uint64) (aptos.AccountAddress, error) {
	accountInfo, err := client.Account(account)
	if err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("failed to get account info: %w", err)
	}
	sequence, err := accountInfo.SequenceNumber()
	if err != nil {
		return aptos.AccountAddress{}, fmt.Errorf("failed to get sequence number: %w", err)
	}

	return calculateNextObjectCodeDeploymentAddress(account, sequence+offset), nil
}

// objectCodeDeploymentPublish calls 0x1::object_code_deployment::publish
// https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/doc/object_code_deployment.md#function-publish
func objectCodeDeploymentPublish(auth aptos.TransactionSigner, client aptos.AptosRpcClient, packageOutput compile.CompiledPackage, options ...any) (*api.PendingTransaction, error) {
	typeArgs, args, err := serializeArgs(nil, []string{"vector<u8>", "vector<vector<u8>>"}, []any{packageOutput.Metadata, packageOutput.Bytecode})
	if err != nil {
		return nil, err
	}

	payload := aptos.TransactionPayload{Payload: &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: aptos.AccountOne,
			Name:    "object_code_deployment",
		},
		Function: "publish",
		ArgTypes: typeArgs,
		Args:     args,
	}}

	return client.BuildSignAndSubmitTransaction(auth, payload, withDefaultDeployGas(options)...)
}

// objectCodeDeploymentUpgrade calls 0x1::object_code_deployment::upgrade
// https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/doc/object_code_deployment.md#function-upgrade
func objectCodeDeploymentUpgrade(auth aptos.TransactionSigner, client aptos.AptosRpcClient, packageOutput compile.CompiledPackage, objectAddress aptos.AccountAddress, options ...any) (*api.PendingTransaction, error) {
	typeArgs, args, err := serializeArgs(nil, []string{"vector<u8>", "vector<vector<u8>>", "address"}, []any{packageOutput.Metadata, packageOutput.Bytecode, objectAddress})
	if err != nil {
		return nil, err
	}

	payload := aptos.TransactionPayload{Payload: &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: aptos.AccountOne,
			Name:    "object_code_deployment",
		},
		Function: "upgrade",
		ArgTypes: typeArgs,
		Args:     args,
	}}

	return client.BuildSignAndSubmitTransaction(auth, payload, withDefaultDeployGas(options)...)
}

// createResourceAccountAndPublishPackage calls 0x1::resource_account::create_resource_account_and_publish_package
// https://github.com/aptos-labs/aptos-core/blob/8d5d045ede6dae476482b2b9c3a80893c521eaa5/aptos-move/framework/aptos-framework/sources/resource_account.move#L124
func createResourceAccountAndPublishPackage(auth aptos.TransactionSigner, client aptos.AptosRpcClient, seed string, packageOutput compile.CompiledPackage, options ...any) (*api.PendingTransaction, error) {
	typeArgs, args, err := serializeArgs(nil, []string{"vector<u8>", "vector<u8>", "vector<vector<u8>>"}, []any{seed, packageOutput.Metadata, packageOutput.Bytecode})
	if err != nil {
		return nil, err
	}

	payload := aptos.TransactionPayload{Payload: &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: aptos.AccountOne,
			Name:    "resource_account",
		},
		Function: "create_resource_account_and_publish_package",
		ArgTypes: typeArgs,
		Args:     args,
	}}

	return client.BuildSignAndSubmitTransaction(auth, payload, withDefaultDeployGas(options)...)
}
