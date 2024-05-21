package txm

import (
	"crypto/ed25519"

	"github.com/aptos-labs/aptos-go-sdk"
)

type AptosTx struct {
	FromAddress     string
	PublicKey       ed25519.PublicKey
	ContractAddress string
	ModuleName      string
	FunctionName    string
	TypeTags        []aptos.TypeTag
	BcsValues       [][]byte
	Attempt         uint64
}
