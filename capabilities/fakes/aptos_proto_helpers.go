package fakes

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	aptoscappb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos"
)

// sdkTransactionToProto maps an aptos-go-sdk transaction to the capability
// proto. Returns nil for nil input or nil Inner (accessors delegate to Inner
// and would nil-deref).
func sdkTransactionToProto(tx *api.Transaction) *aptoscappb.Transaction {
	if tx == nil || tx.Inner == nil {
		return nil
	}
	variant := transactionVariantFromSDK(tx.Type)
	out := &aptoscappb.Transaction{
		Type: variant,
		Hash: tx.Hash(),
	}
	if v := tx.Version(); v != nil {
		vv := *v
		out.Version = &vv
	}
	if s := tx.Success(); s != nil {
		b := *s
		out.Success = &b
	}
	if data, err := json.Marshal(tx.Inner); err == nil {
		out.Data = data
	}
	return out
}

func transactionVariantFromSDK(v api.TransactionVariant) aptoscappb.TransactionVariant {
	switch v {
	case api.TransactionVariantPending:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_PENDING
	case api.TransactionVariantUser:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_USER
	case api.TransactionVariantGenesis:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_GENESIS
	case api.TransactionVariantBlockMetadata:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_BLOCK_METADATA
	case api.TransactionVariantBlockEpilogue:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_BLOCK_EPILOGUE
	case api.TransactionVariantStateCheckpoint:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_STATE_CHECKPOINT
	case api.TransactionVariantValidator:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_VALIDATOR
	default:
		return aptoscappb.TransactionVariant_TRANSACTION_VARIANT_UNKNOWN
	}
}

const moveAbortInPrefix = "move abort in "

// receiverContractExecutionStatusFromFailedVMStatus returns REVERTED for Move
// aborts outside the forwarder module; forwarder-internal aborts yield nil.
func receiverContractExecutionStatusFromFailedVMStatus(vmStatus string, forwarderAddr aptos.AccountAddress, forwarderModule string) *aptoscappb.ReceiverContractExecutionStatus {
	lower := strings.ToLower(vmStatus)
	idx := strings.Index(lower, moveAbortInPrefix)
	if idx < 0 {
		return nil
	}
	rest := strings.TrimSpace(vmStatus[idx+len(moveAbortInPrefix):])
	parts := strings.Split(rest, "::")
	if len(parts) < 2 {
		return nil
	}
	abortModule, err := aptos.ConvertToAddress(strings.TrimSpace(parts[0]))
	if err != nil {
		return nil
	}
	modTok := strings.TrimSpace(parts[1])
	if i := strings.IndexAny(modTok, ": \t"); i >= 0 {
		modTok = modTok[:i]
	}
	if *abortModule == forwarderAddr && modTok == forwarderModule {
		return nil
	}
	rev := aptoscappb.ReceiverContractExecutionStatus_RECEIVER_CONTRACT_EXECUTION_STATUS_REVERTED
	return &rev
}

// viewPayloadFromProto bridges the wire ViewPayload into the sdk ViewPayload.
func viewPayloadFromProto(p *aptoscappb.ViewPayload) (*aptos.ViewPayload, error) {
	if p == nil {
		return nil, fmt.Errorf("viewPayload is nil")
	}
	if p.Module == nil {
		return nil, fmt.Errorf("viewPayload.Module is nil")
	}
	addr, err := addressFromBytes(p.Module.Address)
	if err != nil {
		return nil, fmt.Errorf("viewPayload.Module.Address: %w", err)
	}
	argTypes := make([]aptos.TypeTag, 0, len(p.ArgTypes))
	for _, t := range p.ArgTypes {
		tt, tErr := typeTagFromProto(t)
		if tErr != nil {
			return nil, tErr
		}
		argTypes = append(argTypes, tt)
	}
	return &aptos.ViewPayload{
		Module:   aptos.ModuleId{Address: addr, Name: p.Module.Name},
		Function: p.Function,
		ArgTypes: argTypes,
		Args:     p.Args,
	}, nil
}

func typeTagFromProto(t *aptoscappb.TypeTag) (aptos.TypeTag, error) {
	if t == nil {
		return aptos.TypeTag{}, fmt.Errorf("typeTag is nil")
	}
	switch t.Kind {
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_BOOL:
		return aptos.TypeTag{Value: &aptos.BoolTag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U8:
		return aptos.TypeTag{Value: &aptos.U8Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U16:
		return aptos.TypeTag{Value: &aptos.U16Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U32:
		return aptos.TypeTag{Value: &aptos.U32Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U64:
		return aptos.TypeTag{Value: &aptos.U64Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U128:
		return aptos.TypeTag{Value: &aptos.U128Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_U256:
		return aptos.TypeTag{Value: &aptos.U256Tag{}}, nil
	case aptoscappb.TypeTagKind_TYPE_TAG_KIND_ADDRESS:
		return aptos.TypeTag{Value: &aptos.AddressTag{}}, nil
	default:
		return aptos.TypeTag{}, fmt.Errorf("unsupported TypeTag kind: %v", t.Kind)
	}
}
