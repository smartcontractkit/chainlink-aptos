package failures

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyWriteVmStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		vmStatus     string
		wantDecision WriteFailureDecision
		wantReason   string
		wantMessage  string
	}{
		{
			name:         "non-forwarder abort is terminal",
			vmStatus:     "Move abort in 0xbeef::receiver: E_USER_ABORT",
			wantDecision: WriteFailureDecisionTerminal,
			wantReason:   "receiver or user module aborted",
			wantMessage:  "receiver execution failed",
		},
		{
			name:         "already processed is separate decision",
			vmStatus:     "Move abort in 0xaa::platform::forwarder: E_ALREADY_PROCESSED",
			wantDecision: WriteFailureDecisionAlreadyProcessed,
			wantReason:   "forwarder reported the report was already processed",
			wantMessage:  "already processed by another node",
		},
		{
			name:         "known forwarder validation failure is terminal",
			vmStatus:     "Move abort in 0xaa::platform::forwarder: 65540",
			wantDecision: WriteFailureDecisionTerminal,
			wantReason:   "forwarder reported a terminal validation failure",
			wantMessage:  "signature count was invalid",
		},
		{
			name:         "unknown forwarder abort is retryable",
			vmStatus:     "Move abort in 0xaa::platform::forwarder: 65599",
			wantDecision: WriteFailureDecisionRetryable,
			wantReason:   "forwarder abort was not a known terminal code",
			wantMessage:  "65599",
		},
		{
			name:         "simulation prefix is normalized",
			vmStatus:     "simulated tx unexpected status: Move abort in 0xaa::platform::forwarder: E_CALLBACK_DATA_NOT_CONSUMED",
			wantDecision: WriteFailureDecisionTerminal,
			wantReason:   "forwarder reported a terminal validation failure",
			wantMessage:  "callback data was not consumed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ClassifyWriteVmStatus(tt.vmStatus)
			require.Equal(t, tt.wantDecision, got.Decision)
			require.Equal(t, tt.wantReason, got.Reason)
			require.Contains(t, got.Message, tt.wantMessage)
		})
	}
}
