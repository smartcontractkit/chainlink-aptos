package shared

import "strings"

// ChainSingletonQualifier is the datastore qualifier for types that exist exactly once per chain
const ChainSingletonQualifier = ""

// TokenQualifier returns the datastore qualifier for a token-scoped type: the canonical
// token symbol. Operator input can carry display-name spacing ("CCIP BnM"); the qualifier
// uses the symbol form ("CCIP-BnM") so Aptos rows key identically to the EVM, Solana and
// Sui rows for the same token. Normalising here rather than at each call
// site keeps the two spellings from producing two datastore keys.
func TokenQualifier(symbol string) string {
	return strings.Join(strings.Fields(symbol), "-")
}
