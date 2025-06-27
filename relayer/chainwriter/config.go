package chainwriter

import (
	"github.com/smartcontractkit/chainlink-common/pkg/types/aptos"
)

// Deprecated
//
//go:fix inline
type FeeStrategy = aptos.FeeStrategy

// Deprecated
//
//go:fix inline
const (
	DeprioritizedFeeStrategy = aptos.DeprioritizedFeeStrategy
	DefaultFeeStrategy       = aptos.DefaultFeeStrategy
	PrioritizedFeeStrategy   = aptos.PrioritizedFeeStrategy
)

// Deprecated
//
//go:fix inline
type ChainWriterConfig = aptos.ContractWriterConfig

// Deprecated
//
//go:fix inline
type ChainWriterModule = aptos.ContractWriterModule

// Deprecated
//
//go:fix inline
type ChainWriterFunction = aptos.ContractWriterFunction
