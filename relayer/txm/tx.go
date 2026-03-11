package txm

import (
	"crypto/ed25519"
	"math/big"

	"github.com/aptos-labs/aptos-go-sdk"

	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

type ExpectedSimulationFailureRule struct {
	ErrorContains string
}

type expectedSimulationFailureError struct {
	reason string
}

func (e *expectedSimulationFailureError) Error() string {
	return e.reason
}

type AptosTx struct {
	ID                             string
	Metadata                       *commontypes.TxMeta
	Timestamp                      uint64
	FromAddress                    aptos.AccountAddress
	PublicKey                      ed25519.PublicKey
	ContractAddress                aptos.AccountAddress
	ModuleName                     string
	FunctionName                   string
	TypeTags                       []aptos.TypeTag
	BcsValues                      [][]byte
	Attempt                        uint64
	Status                         commontypes.TransactionStatus
	Simulate                       bool
	ExpectedSimulationFailureRules []ExpectedSimulationFailureRule
	Fee                            *big.Int // Transaction fee in octas (1e-8 APT)
	VmStatus                       string
	TxHash                         string
}
