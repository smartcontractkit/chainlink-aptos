package failures

import commonaptos "github.com/smartcontractkit/chainlink-common/pkg/types/chains/aptos"

type ReceiverExecutionStatus = commonaptos.ReceiverExecutionStatus

const (
	ReceiverExecutionStatusUnknown  = commonaptos.ReceiverExecutionStatusUnknown
	ReceiverExecutionStatusSuccess  = commonaptos.ReceiverExecutionStatusSuccess
	ReceiverExecutionStatusReverted = commonaptos.ReceiverExecutionStatusReverted
)

type WriteFailureDecision = commonaptos.WriteFailureDecision

const (
	WriteFailureDecisionRetryable        = commonaptos.WriteFailureDecisionRetryable
	WriteFailureDecisionTerminal         = commonaptos.WriteFailureDecisionTerminal
	WriteFailureDecisionAlreadyProcessed = commonaptos.WriteFailureDecisionAlreadyProcessed
)

type WriteFailureKind = commonaptos.WriteFailureKind

const (
	WriteFailureKindUnknown           = commonaptos.WriteFailureKindUnknown
	WriteFailureKindForwarderRejected = commonaptos.WriteFailureKindForwarderRejected
	WriteFailureKindReceiverReverted  = commonaptos.WriteFailureKindReceiverReverted
	WriteFailureKindAlreadyProcessed  = commonaptos.WriteFailureKindAlreadyProcessed
)

type WriteFailureClassification = commonaptos.WriteFailureClassification

func ClassifyWriteVmStatus(vmStatus string) WriteFailureClassification {
	return commonaptos.ClassifyWriteVmStatus(vmStatus)
}
