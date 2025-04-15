package bind

import (
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/bindings/compile"
)

const (
	// LargePackagesModuleAddress is the predeployed address of the LargePackages module.
	// It is available on mainnet and testnet only.
	// https://github.com/aptos-labs/aptos-core/blob/e0002dd4ca29d1b65fe10c555ac730a773a54b2f/aptos-move/framework/src/chunked_publish.rs#L9-L9
	LargePackagesModuleAddress = "0x0e1ca3011bdd07246d4d16d909dbb2d6953a86c4735d5acf5865d962c630cce7"
)

type LargePackagesInterface interface {
	StageCodeChunk(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error)
	StageCodeChunkAndPublishToAccount(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error)
	StageCodeChunkAndPublishToObject(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error)
	StageCodeChunkAndUpgradeObjectCode(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error)
}

func DeployOrBindLargePackages(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
) (aptos.AccountAddress, *api.PendingTransaction, LargePackages, error) {
	nodeInfo, err := client.Info()
	if err != nil {
		return aptos.AccountAddress{}, nil, LargePackages{}, err
	}
	switch nodeInfo.ChainId {
	case 1, 2:
		// Mainnet / Testnet
		var predeployedAddress aptos.AccountAddress
		if err := predeployedAddress.ParseStringRelaxed(LargePackagesModuleAddress); err != nil {
			return aptos.AccountAddress{}, nil, LargePackages{}, err
		}
		largePackagesContract := NewBoundContract(predeployedAddress, "large_packages", "large_packages", client)
		return predeployedAddress, nil, LargePackages{Address: predeployedAddress, LargePackagesTransactor: LargePackagesTransactor{BoundContract: largePackagesContract}}, nil
	default:
		return DeployLargePackages(auth, client)
	}
}

func DeployLargePackages(
	auth aptos.TransactionSigner,
	client aptos.AptosRpcClient,
) (aptos.AccountAddress, *api.PendingTransaction, LargePackages, error) {
	// Calculate named addresses
	address, err := nextObjectCodeDeploymentAddressForAccount(client, auth.AccountAddress(), 0)
	if err != nil {
		return aptos.AccountAddress{}, nil, LargePackages{}, err
	}

	// Compile using CLI
	output, err := compile.CompilePackage("large_packages", map[string]aptos.AccountAddress{
		"large_packages": address,
	})
	if err != nil {
		return aptos.AccountAddress{}, nil, LargePackages{}, err
	}

	tx, err := objectCodeDeploymentPublish(auth, client, output)
	if err != nil {
		return aptos.AccountAddress{}, nil, LargePackages{}, err
	}

	largePackagesContract := NewBoundContract(address, "large_packages", "large_packages", client)
	return address, tx, LargePackages{Address: address, LargePackagesTransactor: LargePackagesTransactor{BoundContract: largePackagesContract}}, nil
}

type LargePackages struct {
	Address aptos.AccountAddress

	LargePackagesTransactor
}

type LargePackagesTransactor struct {
	*BoundContract
}

func (l LargePackagesTransactor) StageCodeChunk(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := l.Encode(
		"stage_code_chunk",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
		})
	if err != nil {
		return nil, err
	}
	return l.Transact(opts, module, function, typeTags, args)
}

func (l LargePackagesTransactor) StageCodeChunkAndPublishToAccount(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := l.Encode(
		"stage_code_chunk_and_publish_to_account",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
		})
	if err != nil {
		return nil, err
	}
	return l.Transact(opts, module, function, typeTags, args)
}

func (l LargePackagesTransactor) StageCodeChunkAndPublishToObject(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := l.Encode(
		"stage_code_chunk_and_publish_to_object",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
		})
	if err != nil {
		return nil, err
	}
	return l.Transact(opts, module, function, typeTags, args)
}

func (l LargePackagesTransactor) StageCodeChunkAndUpgradeObjectCode(opts *TransactOpts, metadataChunk []byte, codeIndices []uint16, codeChunks [][]byte, objectAddress aptos.AccountAddress) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := l.Encode(
		"stage_code_chunk_and_upgrade_object_code",
		nil,
		[]string{
			"vector<u8>",
			"vector<u16>",
			"vector<vector<u8>>",
			"address",
		},
		[]any{
			metadataChunk,
			codeIndices,
			codeChunks,
			objectAddress,
		})
	if err != nil {
		return nil, err
	}
	return l.Transact(opts, module, function, typeTags, args)
}

func (l LargePackagesTransactor) CleanupStagingArea(opts *TransactOpts) (*api.PendingTransaction, error) {
	module, function, typeTags, args, err := l.Encode(
		"cleanup_staging_area",
		nil,
		[]string{},
		[]any{},
	)
	if err != nil {
		return nil, err
	}
	return l.Transact(opts, module, function, typeTags, args)
}
