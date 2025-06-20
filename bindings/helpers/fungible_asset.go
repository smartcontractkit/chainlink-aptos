package helpers

import (
	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

// GetFungibleAssetBalance queries the given account's balance of the fungible asset in its primary fungible store.
func GetFungibleAssetBalance(
	client aptos.AptosRpcClient,
	account aptos.AccountAddress,
	faMetadataAddress aptos.AccountAddress,
) (uint64, error) {
	bc := bind.NewBoundContract(
		aptos.AccountOne,
		"std",
		"primary_fungible_store",
		client,
	)
	module, function, typeTags, args, err := bc.Encode(
		"balance",
		[]string{
			"0x1::fungible_asset::Metadata",
		},
		[]string{
			"address",
			"address",
		}, []any{
			account,
			faMetadataAddress,
		})
	if err != nil {
		return 0, err
	}
	callData, err := bc.Call(nil, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var balance uint64
	if err := codec.DecodeAptosJsonArray(callData, &balance); err != nil {
		return 0, err
	}
	return balance, nil
}

type FungibleAssetMetadata struct {
	Name       string
	Symbol     string
	Decimals   uint8
	IconURI    string
	ProjectURI string
}

func GetFungibleAssetMetadata(
	client aptos.AptosRpcClient,
	faMetadataAddress aptos.AccountAddress,
) (FungibleAssetMetadata, error) {
	bc := bind.NewBoundContract(
		aptos.AccountOne,
		"std",
		"fungible_asset",
		client,
	)
	module, function, typeTags, args, err := bc.Encode(
		"metadata",
		[]string{
			"0x1::fungible_asset::Metadata",
		},
		[]string{
			"address",
		}, []any{
			faMetadataAddress,
		})
	callData, err := bc.Call(nil, module, function, typeTags, args)
	if err != nil {
		return FungibleAssetMetadata{}, err
	}

	var metadata FungibleAssetMetadata
	if err := codec.DecodeAptosJsonArray(callData, &metadata); err != nil {
		return FungibleAssetMetadata{}, err
	}
	return metadata, nil
}

func GetFungibleAssetSupply(
	client aptos.AptosRpcClient,
	faMetadataAddress aptos.AccountAddress,
) (uint64, error) {
	bc := bind.NewBoundContract(
		aptos.AccountOne,
		"std",
		"fungible_asset",
		client,
	)
	module, function, typeTags, args, err := bc.Encode(
		"supply",
		[]string{
			"0x1::fungible_asset::Metadata",
		},
		[]string{
			"address",
		}, []any{
			faMetadataAddress,
		})
	if err != nil {
		return 0, err
	}
	callData, err := bc.Call(nil, module, function, typeTags, args)
	if err != nil {
		return 0, err
	}

	var supply bind.StdOption[uint64]
	if err := codec.DecodeAptosJsonArray(callData, &supply); err != nil {
		return 0, err
	}
	return *supply.Value(), nil
}
