package codec

import "github.com/smartcontractkit/chainlink-aptos/codec"

// Deprecated: use codec.DecodeAptosJsonArray
//
//go:fix inline
func DecodeAptosJsonArray(from []any, to ...any) error {
	return codec.DecodeAptosJsonArray(from, to...)
}

// Deprecated: use codec.DecodeAptosJsonValue
//
//go:fix inline
func DecodeAptosJsonValue(from any, to any) error {
	return codec.DecodeAptosJsonValue(from, to)
}
