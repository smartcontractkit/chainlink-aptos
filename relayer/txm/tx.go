package txm

import (
	txbuilder "github.com/coming-chat/go-aptos/transaction_builder"
)

type AptosTx struct {
	FromAddress     string
	ContractAddress string
	ModuleName      string
	FunctionName    string
	TypeTags        []txbuilder.TypeTag
	BcsValues       [][]byte
	Attempt         uint64
}
