package txm

import (
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
)

func GetContexedTxLogger(baseLogger logger.Logger, txID string, txMetadata *commontypes.TxMeta) logger.Logger {
	workflowExecutionID := "unknown"
	if txMetadata != nil && txMetadata.WorkflowExecutionID != nil {
		workflowExecutionID = *txMetadata.WorkflowExecutionID
	}
	return logger.With(baseLogger, "txID", txID, "workflowExecutionID", workflowExecutionID)
}
