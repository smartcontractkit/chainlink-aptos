package txm

import (
	"crypto/ed25519"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

type AptosTx struct {
	ID              string
	Metadata        *commontypes.TxMeta
	Timestamp       uint64
	FromAddress     aptos.AccountAddress
	PublicKey       ed25519.PublicKey
	ContractAddress aptos.AccountAddress
	ModuleName      string
	FunctionName    string
	TypeTags        []aptos.TypeTag
	BcsValues       [][]byte
	// Payload, when set, is used directly instead of reconstructing an EntryFunction from ModuleName/FunctionName/Args.
	Payload              *aptos.TransactionPayload
	GasUnitPriceOverride *uint64
	Attempt              uint64
	Status               commontypes.TransactionStatus
	Simulate             bool
	Fee                  *big.Int // Transaction fee in octas (1e-8 APT)

	LastSubmittedHash                    string
	LastSubmittedNonce                   uint64
	LastSubmittedExpirationTimestampSecs uint64
	LastSubmittedMaxGasAmount            uint64
	LastSubmittedGasUnitPrice            uint64
	LastSubmittedSignature               []byte
}
