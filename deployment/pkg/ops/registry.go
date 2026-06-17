package ops

import (
	"github.com/smartcontractkit/chainlink-deployments-framework/operations"

	"github.com/smartcontractkit/chainlink-aptos/deployment/ccip/operation"
)

var Registry = operations.NewOperationRegistry(operation.GetAptosOperations()...)
