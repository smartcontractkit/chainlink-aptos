package txm

import (
	"crypto/ed25519"

	txbuilder "github.com/coming-chat/go-aptos/transaction_builder"
)

type AptosTx struct {
	FromAddress     string
	PublicKey       ed25519.PublicKey
	ContractAddress string
	ModuleName      string
	FunctionName    string
	TypeTags        []txbuilder.TypeTag
	BcsValues       [][]byte
	Attempt         uint64
}
