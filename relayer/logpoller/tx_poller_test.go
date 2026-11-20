package logpoller

import (
	"testing"

	aptos "github.com/aptos-labs/aptos-go-sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreDispatchAbort(t *testing.T) {
	t.Parallel()

	var offRamp aptos.AccountAddress
	require.NoError(t, offRamp.ParseStringRelaxed("0xa1"))
	zeroPaddedOffRamp := "0x00000000000000000000000000000000000000000000000000000000000000a1"

	tests := []struct {
		name     string
		vmStatus string
		want     bool
	}{
		{
			name:     "unknown source chain selector is pre-dispatch",
			vmStatus: "Move abort in 0xa1::offramp: E_UNKNOWN_SOURCE_CHAIN_SELECTOR(0x10004) at code offset 30",
			want:     true,
		},
		{
			name:     "token data mismatch is pre-dispatch",
			vmStatus: "Move abort in 0xa1::offramp: E_TOKEN_DATA_MISMATCH(0x10008)",
			want:     true,
		},
		{
			name:     "root not committed is pre-dispatch",
			vmStatus: "Move abort in 0xa1::offramp: E_ROOT_NOT_COMMITTED(0x10009) at code offset 12",
			want:     true,
		},
		{
			name:     "source chain not enabled is pre-dispatch",
			vmStatus: "Move abort in 0xa1::offramp: E_SOURCE_CHAIN_NOT_ENABLED(0x5000b)",
			want:     true,
		},
		{
			name:     "Move abort in 0xa1::offramp: E_UNSUPPORTED_TOKEN(0x30011)",
			vmStatus: "Move abort in 0xa1::offramp: E_UNSUPPORTED_TOKEN(0x30011)",
			want:     true,
		},
		{
			name:     "Move abort in 0xa1::offramp: E_FUNGIBLE_ASSET_TYPE_MISMATCH(0x30014)",
			vmStatus: "Move abort in 0xa1::offramp: E_FUNGIBLE_ASSET_TYPE_MISMATCH(0x30014)",
			want:     true,
		},
		{
			name:     "Move abort in 0xa1::offramp: E_FUNGIBLE_ASSET_AMOUNT_MISMATCH(0x30015)",
			vmStatus: "Move abort in 0xa1::offramp: E_FUNGIBLE_ASSET_AMOUNT_MISMATCH(0x30015)",
			want:     true,
		},
		{
			name:     "zero padded offramp address still places the abort",
			vmStatus: "Move abort in " + zeroPaddedOffRamp + "::offramp: E_ROOT_NOT_COMMITTED(0x10009)",
			want:     true,
		},
		{
			name:     "abort in an offramp function is pre-dispatch when the code is",
			vmStatus: "Move abort in 0xa1::offramp::execute_single_report: E_ROOT_NOT_COMMITTED(0x10009)",
			want:     true,
		},
		{
			name:     "receiver induced abort inside the offramp is a failure",
			vmStatus: "Move abort in 0xa1::offramp::calculate_message_hash: E_CALCULATE_MESSAGE_HASH_INVALID_ARGUMENTS(0x1001a)",
			want:     false,
		},
		{
			name:     "runtime failure in the offramp is a failure",
			vmStatus: "Execution failed in 0xa1::offramp::execute at code offset 12: REENTRANCY_NOT_ALLOWED(4037)",
			want:     false,
		},
		{
			name:     "other offramp abort codes are failures",
			vmStatus: "Move abort in 0xa1::offramp: E_DEST_CHAIN_SELECTOR_MISMATCH(0x10007)",
			want:     false,
		},
		{
			name:     "abort at the receiver is a failure",
			vmStatus: "Move abort in 0xd4::receiver: E_REJECTED(0x1)",
			want:     false,
		},
		{
			name:     "abort at the ccip package is a failure",
			vmStatus: "Move abort in 0x2::ccip: E_INVALID_MESSAGE(0x1000c)",
			want:     false,
		},
		{
			name:     "abort naming the offramp outside its location is a failure",
			vmStatus: "Move abort in 0xd4::receiver: E_SOME_ERROR(0x1) at code offset 8 in 0xa1::offramp",
			want:     false,
		},
		{
			name:     "abort without a code is a failure",
			vmStatus: "Move abort in 0xa1::offramp",
			want:     false,
		},
		{
			name:     "bare hex code without error metadata is pre-dispatch",
			vmStatus: "Move abort in 0xa1::offramp: 0x10009",
			want:     true,
		},
		{
			name:     "bare hex code at a non-skip code is a failure",
			vmStatus: "Move abort in 0xa1::offramp: 0x1001a",
			want:     false,
		},
		{
			name:     "unparseable status is a failure",
			vmStatus: "Out of gas",
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, test.want, preDispatchAbort(test.vmStatus, offRamp, "offramp"))
		})
	}
}
