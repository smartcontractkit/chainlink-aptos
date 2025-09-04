package helpers

import (
	"github.com/aptos-labs/aptos-go-sdk"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	"github.com/smartcontractkit/chainlink-aptos/relayer/codec"
)

func GetObjectOwner(
	client aptos.AptosRpcClient,
	objectAddress aptos.AccountAddress,
) (aptos.AccountAddress, error) {
	bc := bind.NewBoundContract(
		aptos.AccountOne,
		"std",
		"object",
		client,
	)
	module, function, typeTags, args, err := bc.Encode(
		"owner",
		[]string{
			"0x1::object::ObjectCore",
		},
		[]string{
			"address",
		}, []any{
			objectAddress,
		})
	callData, err := bc.Call(nil, module, function, typeTags, args)
	if err != nil {
		return aptos.AccountAddress{}, err
	}

	var owner aptos.AccountAddress
	if err := codec.DecodeAptosJsonArray(callData, &owner); err != nil {
		return aptos.AccountAddress{}, err
	}
	return owner, nil
}
