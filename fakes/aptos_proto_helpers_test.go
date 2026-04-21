package fakes

import (
	"encoding/hex"
	"testing"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aptoscappb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos"
)

func TestTransactionVariantFromSDK_AllKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   api.TransactionVariant
		want aptoscappb.TransactionVariant
	}{
		{api.TransactionVariantPending, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_PENDING},
		{api.TransactionVariantUser, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_USER},
		{api.TransactionVariantGenesis, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_GENESIS},
		{api.TransactionVariantBlockMetadata, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_BLOCK_METADATA},
		{api.TransactionVariantBlockEpilogue, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_BLOCK_EPILOGUE},
		{api.TransactionVariantStateCheckpoint, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_STATE_CHECKPOINT},
		{api.TransactionVariantValidator, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_VALIDATOR},
		{api.TransactionVariant("unknown-future-variant"), aptoscappb.TransactionVariant_TRANSACTION_VARIANT_UNKNOWN},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, transactionVariantFromSDK(c.in), "variant %q", c.in)
	}
}

func userTx(hash string, version uint64, success bool) *api.Transaction {
	return &api.Transaction{
		Type: api.TransactionVariantUser,
		Inner: &api.UserTransaction{
			Hash:    hash,
			Version: version,
			Success: success,
		},
	}
}

func TestSDKTransactionToProto_UserSuccess(t *testing.T) {
	t.Parallel()
	got := sdkTransactionToProto(userTx("0xabc", 42, true))
	require.NotNil(t, got)
	assert.Equal(t, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_USER, got.Type)
	assert.Equal(t, "0xabc", got.Hash)
	require.NotNil(t, got.Version)
	assert.Equal(t, uint64(42), *got.Version)
	require.NotNil(t, got.Success)
	assert.True(t, *got.Success)
	assert.NotEmpty(t, got.Data)
}

func TestSDKTransactionToProto_Pending(t *testing.T) {
	t.Parallel()
	tx := &api.Transaction{
		Type:  api.TransactionVariantPending,
		Inner: &api.PendingTransaction{Hash: "0xpending"},
	}
	got := sdkTransactionToProto(tx)
	require.NotNil(t, got)
	assert.Equal(t, aptoscappb.TransactionVariant_TRANSACTION_VARIANT_PENDING, got.Type)
	assert.Nil(t, got.Success)
	assert.Nil(t, got.Version)
}

func TestSDKTransactionToProto_Nil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, sdkTransactionToProto(nil))
}

// Regression: a non-nil Transaction with nil Inner must not panic. All three
// accessors (Hash / Version / Success) delegate to Inner via TransactionImpl,
// and a nil interface value dereferences. Treat this shape as no-data.
func TestSDKTransactionToProto_NilInner(t *testing.T) {
	t.Parallel()
	tx := &api.Transaction{Type: api.TransactionVariantUnknown}
	assert.NotPanics(t, func() {
		got := sdkTransactionToProto(tx)
		assert.Nil(t, got)
	})
}

func TestReceiverStatusFromFailedVMStatus_NotMoveAbort(t *testing.T) {
	t.Parallel()
	assert.Nil(t, receiverContractExecutionStatusFromFailedVMStatus("arbitrary error", aptos.AccountAddress{}))
}

func TestReceiverStatusFromFailedVMStatus_ForwarderAbortIsNil(t *testing.T) {
	t.Parallel()
	var fwd aptos.AccountAddress
	require.NoError(t, fwd.ParseStringRelaxed("0x010203"))
	status := "Move abort in 0x010203::forwarder: EBadSig"
	assert.Nil(t, receiverContractExecutionStatusFromFailedVMStatus(status, fwd))
}

func TestReceiverStatusFromFailedVMStatus_ReceiverAbortYieldsReverted(t *testing.T) {
	t.Parallel()
	var fwd aptos.AccountAddress
	require.NoError(t, fwd.ParseStringRelaxed("0x010203"))
	status := "Move abort in 0xdeadbeef::receiver: EReject"
	got := receiverContractExecutionStatusFromFailedVMStatus(status, fwd)
	require.NotNil(t, got)
	assert.Equal(t,
		aptoscappb.ReceiverContractExecutionStatus_RECEIVER_CONTRACT_EXECUTION_STATUS_REVERTED,
		*got)
}

func TestReceiverStatusFromFailedVMStatus_GarbageAfterPrefix(t *testing.T) {
	t.Parallel()
	assert.Nil(t, receiverContractExecutionStatusFromFailedVMStatus("move abort in garbage", aptos.AccountAddress{}))
}

func TestViewPayloadFromProto_Minimal(t *testing.T) {
	t.Parallel()
	addr, err := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	require.NoError(t, err)
	p, err := viewPayloadFromProto(&aptoscappb.ViewPayload{
		Module:   &aptoscappb.ModuleID{Address: addr, Name: "coin"},
		Function: "balance",
	})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "coin", p.Module.Name)
	assert.Equal(t, "balance", p.Function)
}

func TestViewPayloadFromProto_NilModule(t *testing.T) {
	t.Parallel()
	_, err := viewPayloadFromProto(&aptoscappb.ViewPayload{Function: "f"})
	require.Error(t, err)
}

func TestViewPayloadFromProto_NilPayload(t *testing.T) {
	t.Parallel()
	_, err := viewPayloadFromProto(nil)
	require.Error(t, err)
}

func TestViewPayloadFromProto_BadAddressLength(t *testing.T) {
	t.Parallel()
	_, err := viewPayloadFromProto(&aptoscappb.ViewPayload{
		Module:   &aptoscappb.ModuleID{Address: []byte{1, 2, 3}, Name: "x"},
		Function: "f",
	})
	require.Error(t, err)
}

func TestTypeTagFromProto_AllKinds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		kind aptoscappb.TypeTagKind
	}{
		{"bool", aptoscappb.TypeTagKind_TYPE_TAG_KIND_BOOL},
		{"u8", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U8},
		{"u16", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U16},
		{"u32", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U32},
		{"u64", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U64},
		{"u128", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U128},
		{"u256", aptoscappb.TypeTagKind_TYPE_TAG_KIND_U256},
		{"address", aptoscappb.TypeTagKind_TYPE_TAG_KIND_ADDRESS},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tag, err := typeTagFromProto(&aptoscappb.TypeTag{Kind: tc.kind})
			require.NoError(t, err)
			require.NotNil(t, tag.Value)
		})
	}
}

func TestTypeTagFromProto_Nil(t *testing.T) {
	t.Parallel()
	_, err := typeTagFromProto(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typeTag is nil")
}

func TestTypeTagFromProto_Unsupported(t *testing.T) {
	t.Parallel()
	_, err := typeTagFromProto(&aptoscappb.TypeTag{Kind: aptoscappb.TypeTagKind_TYPE_TAG_KIND_SIGNER})
	require.Error(t, err)
}

func TestViewPayloadFromProto_BadArgTypePropagates(t *testing.T) {
	t.Parallel()
	addr, err := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101")
	require.NoError(t, err)
	_, err = viewPayloadFromProto(&aptoscappb.ViewPayload{
		Module:   &aptoscappb.ModuleID{Address: addr, Name: "coin"},
		Function: "balance",
		ArgTypes: []*aptoscappb.TypeTag{{Kind: aptoscappb.TypeTagKind_TYPE_TAG_KIND_SIGNER}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported TypeTag kind")
}
