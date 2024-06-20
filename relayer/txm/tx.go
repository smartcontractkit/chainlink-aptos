package txm

import (
	"crypto/ed25519"

	"github.com/aptos-labs/aptos-go-sdk"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

const (
	// TransmitCheckerTypeSimulate is a checker that simulates the transaction before executing on
	// chain.
	TransmitCheckerTypeSimulate = TransmitCheckerType("simulate")
)

// TransmitCheckerType describes the type of check that should be performed before a transaction is
// executed on-chain.
type TransmitCheckerType string

type TransmitCheckerSpec struct {
	// CheckerType is the type of check that should be performed. Empty indicates no check.
	CheckerType TransmitCheckerType `json:",omitempty"`
}

type AptosTx struct {
	ID              string
	Timestamp       uint64
	FromAddress     aptos.AccountAddress
	PublicKey       ed25519.PublicKey
	ContractAddress aptos.AccountAddress
	ModuleName      string
	FunctionName    string
	TypeTags        []aptos.TypeTag
	BcsValues       [][]byte
	Attempt         uint64
	Status          commontypes.TransactionStatus
	// Checker defines the check that should be run before a transaction is submitted on chain.
	Checker TransmitCheckerSpec
}
