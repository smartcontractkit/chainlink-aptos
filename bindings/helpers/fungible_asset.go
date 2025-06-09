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
