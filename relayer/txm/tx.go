package txm

import (
	"crypto/ed25519"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/google/uuid"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

type AptosTx struct {
	ID              uuid.UUID
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
