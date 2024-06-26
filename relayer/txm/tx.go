package txm

import (
	"crypto/ed25519"

	"github.com/aptos-labs/aptos-go-sdk"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

type AptosTx struct {
	ID              string
	Timestamp       uint64
	FromAddress     string
	PublicKey       ed25519.PublicKey
	ContractAddress string
	ModuleName      string
	FunctionName    string
	TypeTags        []aptos.TypeTag
	BcsValues       [][]byte
	Attempt         uint64
	Status          commontypes.TransactionStatus
}
