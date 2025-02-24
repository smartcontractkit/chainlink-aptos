# Aptos contract bindings

This package contains bindings for all Aptos contracts. It is used to deploy and interact with deployed contracts.

## Supported packages

Each Move package is separated in its own directory:
- mcms
- ccip

With the packages' modules being in separate subdirectories, each strictly named after the module's name:
- mcms/mcms: `@mcms::mcms`
- mcms/mcms_account: `@mcms::mcms_account`
- mcms/mcms_deployer: `@mcms::mcms_deployer`
- ...

Deployment and bindings happen at the package level, all modules will be deployed/bound at once.

## Usage

### Compiling contracts

To compile a package, use the `Compile()` function in the package's directory.
Compilation will use the Aptos CLI, it is required to be installed and available in the PATH.

### Binding deployed contracts

To bind an already deployed package, use the `Bind()` function in the package's directory.

### Interacting with contracts

To transact with a contract/call a view method on a contract, use the bound contract:
```go
// Create the bound contract
mcmsContract := mcms.Bind(mcmsAddress, rpcClient)

// Call a view method
owner, err := mcmsContract.MCMSAccount.Owner(nil)
if err != nil {
	panic(er)
}
fmt.Println(owner)

// Transact with the contract
opts := &bind.TransactOpts{Signer: deployerAccount}
tx, err := mcmsContract.MCMSAccount.TransferOwnership(opts, newOwner)
if err != nil {
    panic(err)
}

data, err := rpcClient.WaitForTransaction(tx.Hash)
if err != nil {
    panic(err)
}
if !data.Success {
	panic(data.VmStatus)
}

fmt.Printf("Ownership transfer requested in tx %v\n", tx.Hash)
```

Every method will have a corresponding `Encode` method to just encode the call/transaction data without submitting it.
This is useful when interacting with a contract via MCMS. To encode a call, use the `Encode` method on the bound
contract and then use the returned values to submit a transaction via MCMS:
```go
// Encode the accept ownership call, to be submitted via MCMS
module, function, _, args, err := mcmsContract.MCMSAccount.EncodeAcceptOwnership()
if err != nil {
	panic(err)
}

// Now create a new mcms proposal and add the encoded call as an operation.
fmt.Println("Target address:", module.Address)
fmt.Println("Target module:", module.Name)
fmt.Println("Target function:", function)
fmt.Println("Data: ", module_mcms.ArgsToData(args))
```