package fakes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/crypto"

	commonCap "github.com/smartcontractkit/chainlink-common/pkg/capabilities"
	caperrors "github.com/smartcontractkit/chainlink-common/pkg/capabilities/errors"
	aptoscappb "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos"
	aptosserver "github.com/smartcontractkit/chainlink-common/pkg/capabilities/v2/chain-capabilities/aptos/server"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"

	"github.com/smartcontractkit/chainlink-aptos/bindings/bind"
	mockfwd "github.com/smartcontractkit/chainlink-aptos/bindings/platform_mock/mock_forwarder"
)

const mockForwarderModuleName = "mock_forwarder"

// FakeAptosChain implements aptosserver.ClientCapability via aptos-go-sdk and
// a user-published mock_forwarder. Counterpart to FakeEVMChain.
type FakeAptosChain struct {
	commonCap.CapabilityInfo
	services.Service
	eng *services.Engine

	client           aptos.AptosRpcClient
	privateKey       *crypto.Ed25519PrivateKey
	account          *aptos.Account
	mockForwarder    mockfwd.MockForwarderInterface
	forwarderAddress aptos.AccountAddress
	chainSelector    uint64
	dryRunWrites     bool
}

var (
	_ services.Service               = (*FakeAptosChain)(nil)
	_ aptosserver.ClientCapability   = (*FakeAptosChain)(nil)
	_ commonCap.ExecutableCapability = (*FakeAptosChain)(nil)
)

// NewFakeAptosChain wires a FakeAptosChain to `client` and the mock forwarder
// at `forwarderAddress`. `dryRunWrites=true` routes WriteReport through
// SimulateTransaction instead of SubmitTransaction.
func NewFakeAptosChain(
	lggr logger.Logger,
	client aptos.AptosRpcClient,
	privateKey *crypto.Ed25519PrivateKey,
	forwarderAddress aptos.AccountAddress,
	chainSelector uint64,
	dryRunWrites bool,
) (*FakeAptosChain, error) {
	if client == nil {
		return nil, fmt.Errorf("aptos client is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	info, err := commonCap.NewCapabilityInfo(
		fmt.Sprintf("aptos:ChainSelector:%d@1.0.0", chainSelector),
		commonCap.CapabilityTypeCombined,
		"A fake Aptos chain capability",
	)
	if err != nil {
		return nil, fmt.Errorf("new capability info: %w", err)
	}
	acct, err := aptos.NewAccountFromSigner(privateKey)
	if err != nil {
		return nil, fmt.Errorf("build aptos account: %w", err)
	}
	fwd := mockfwd.NewMockForwarder(forwarderAddress, client)

	fc := &FakeAptosChain{
		CapabilityInfo:   info,
		client:           client,
		privateKey:       privateKey,
		account:          acct,
		mockForwarder:    fwd,
		forwarderAddress: forwarderAddress,
		chainSelector:    chainSelector,
		dryRunWrites:     dryRunWrites,
	}
	fc.Service, fc.eng = services.Config{
		Name:  fmt.Sprintf("FakeAptosChain.%d", chainSelector),
		Start: fc.start,
		Close: fc.close,
	}.NewServiceEngine(lggr)
	return fc, nil
}

func (fc *FakeAptosChain) start(_ context.Context) error {
	fc.eng.Debugw("Aptos Chain started")
	return nil
}

func (fc *FakeAptosChain) close() error {
	fc.eng.Debugw("Aptos Chain closed")
	return nil
}

func (fc *FakeAptosChain) ChainSelector() uint64 { return fc.chainSelector }
func (fc *FakeAptosChain) Description() string   { return fc.CapabilityInfo.Description }
func (fc *FakeAptosChain) Name() string          { return fc.ID }
func (fc *FakeAptosChain) Initialise(ctx context.Context, _ core.StandardCapabilitiesDependencies) error {
	return fc.Start(ctx)
}

func (fc *FakeAptosChain) RegisterToWorkflow(_ context.Context, request commonCap.RegisterToWorkflowRequest) error {
	fc.eng.Infow("Registered to Aptos Chain", "workflowID", request.Metadata.WorkflowID)
	return nil
}

func (fc *FakeAptosChain) UnregisterFromWorkflow(_ context.Context, request commonCap.UnregisterFromWorkflowRequest) error {
	fc.eng.Infow("Unregistered from Aptos Chain", "workflowID", request.Metadata.WorkflowID)
	return nil
}

func (fc *FakeAptosChain) Execute(_ context.Context, request commonCap.CapabilityRequest) (commonCap.CapabilityResponse, error) {
	fc.eng.Infow("Aptos Chain executed", "request", request)
	return commonCap.CapabilityResponse{}, nil
}

// isNotFound detects "transaction not found" across aptos-go-sdk error-wrapping
// variants. Prefers typed check; falls back to status / message substring so
// wrapped or transport-layer 404s still classify correctly.
func isNotFound(err error) bool {
	var httpErr *aptos.HttpError
	if errors.As(err, &httpErr) && httpErr.StatusCode == 404 {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") || strings.Contains(msg, "not found")
}

// addressFromBytes copies a 32-byte slice into an aptos.AccountAddress.
func addressFromBytes(b []byte) (aptos.AccountAddress, error) {
	var a aptos.AccountAddress
	if len(b) != 32 {
		return a, fmt.Errorf("address must be 32 bytes, got %d", len(b))
	}
	copy(a[:], b)
	return a, nil
}

func (fc *FakeAptosChain) AccountAPTBalance(
	_ context.Context,
	_ commonCap.RequestMetadata,
	input *aptoscappb.AccountAPTBalanceRequest,
) (*commonCap.ResponseAndMetadata[*aptoscappb.AccountAPTBalanceReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain AccountAPTBalance Started", "input", input)
	if input == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("accountAPTBalanceRequest is nil"), caperrors.InvalidArgument)
	}
	addr, err := addressFromBytes(input.Address)
	if err != nil {
		return nil, caperrors.NewPublicUserError(err, caperrors.InvalidArgument)
	}
	value, err := fc.client.AccountAPTBalance(addr)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("aptos balance: %w", err), caperrors.Unavailable)
	}
	return &commonCap.ResponseAndMetadata[*aptoscappb.AccountAPTBalanceReply]{
		Response: &aptoscappb.AccountAPTBalanceReply{Value: value},
	}, nil
}

func (fc *FakeAptosChain) View(
	_ context.Context,
	_ commonCap.RequestMetadata,
	input *aptoscappb.ViewRequest,
) (*commonCap.ResponseAndMetadata[*aptoscappb.ViewReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain View Started", "input", input)
	if input == nil || input.Payload == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("viewRequest missing payload"), caperrors.InvalidArgument)
	}
	payload, err := viewPayloadFromProto(input.Payload)
	if err != nil {
		return nil, caperrors.NewPublicUserError(err, caperrors.InvalidArgument)
	}
	var ledger []uint64
	if input.LedgerVersion != nil {
		ledger = []uint64{*input.LedgerVersion}
	}
	result, err := fc.client.View(payload, ledger...)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("aptos view %s::%s: %w", payload.Module.Name, payload.Function, err), caperrors.Unavailable)
	}
	data, mErr := json.Marshal(result)
	if mErr != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("marshal view result: %w", mErr), caperrors.Internal)
	}
	fc.eng.Infow("Aptos Chain View Finished", "data", data)
	return &commonCap.ResponseAndMetadata[*aptoscappb.ViewReply]{
		Response: &aptoscappb.ViewReply{Data: data},
	}, nil
}

func (fc *FakeAptosChain) TransactionByHash(
	_ context.Context,
	_ commonCap.RequestMetadata,
	input *aptoscappb.TransactionByHashRequest,
) (*commonCap.ResponseAndMetadata[*aptoscappb.TransactionByHashReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain TransactionByHash Started", "input", input)
	if input == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("transactionByHashRequest is nil"), caperrors.InvalidArgument)
	}
	if input.Hash == "" {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("transactionByHashRequest.hash must not be empty"), caperrors.InvalidArgument)
	}
	tx, err := fc.client.TransactionByHash(input.Hash)
	if err != nil {
		if isNotFound(err) {
			return &commonCap.ResponseAndMetadata[*aptoscappb.TransactionByHashReply]{
				Response: &aptoscappb.TransactionByHashReply{Transaction: nil},
			}, nil
		}
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("aptos transaction_by_hash %s: %w", input.Hash, err), caperrors.Unavailable)
	}
	fc.eng.Infow("Aptos Chain TransactionByHash Finished", "transaction", tx)
	return &commonCap.ResponseAndMetadata[*aptoscappb.TransactionByHashReply]{
		Response: &aptoscappb.TransactionByHashReply{Transaction: sdkTransactionToProto(tx)},
	}, nil
}

func (fc *FakeAptosChain) AccountTransactions(
	_ context.Context,
	_ commonCap.RequestMetadata,
	input *aptoscappb.AccountTransactionsRequest,
) (*commonCap.ResponseAndMetadata[*aptoscappb.AccountTransactionsReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain AccountTransactions Started", "input", input)
	if input == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("accountTransactionsRequest is nil"), caperrors.InvalidArgument)
	}
	addr, err := addressFromBytes(input.Address)
	if err != nil {
		return nil, caperrors.NewPublicUserError(err, caperrors.InvalidArgument)
	}

	start, limit, capErr := fc.accountTransactionsWindow(addr, input.Start, input.Limit)
	if capErr != nil {
		return nil, capErr
	}
	if limit != nil && *limit == 0 {
		return &commonCap.ResponseAndMetadata[*aptoscappb.AccountTransactionsReply]{
			Response: &aptoscappb.AccountTransactionsReply{},
		}, nil
	}
	committed, err := fc.client.AccountTransactions(addr, start, limit)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("aptos account_transactions %s: %w", addr.String(), err), caperrors.Unavailable)
	}
	out := make([]*aptoscappb.Transaction, 0, len(committed))
	dropped := 0
	for _, tx := range committed {
		if tx == nil {
			dropped++
			continue
		}
		t := &api.Transaction{Type: tx.Type, Inner: tx.Inner}
		mapped := sdkTransactionToProto(t)
		if mapped == nil {
			dropped++
			continue
		}
		out = append(out, mapped)
	}
	if dropped > 0 {
		fc.eng.Warnw("Aptos Chain AccountTransactions dropped items", "dropped", dropped, "kept", len(out))
	}
	fc.eng.Infow("Aptos Chain AccountTransactions Finished", "count", len(out))
	return &commonCap.ResponseAndMetadata[*aptoscappb.AccountTransactionsReply]{
		Response: &aptoscappb.AccountTransactionsReply{Transactions: out},
	}, nil
}

func (fc *FakeAptosChain) accountTransactionsWindow(
	address aptos.AccountAddress,
	start *uint64,
	limit *uint64,
) (*uint64, *uint64, caperrors.Error) {
	if start != nil || limit == nil {
		return start, limit, nil
	}

	accountInfo, err := fc.client.Account(address)
	if err != nil {
		return nil, nil, caperrors.NewPublicSystemError(fmt.Errorf("failed to get account info: %w", err), caperrors.Unavailable)
	}
	sequenceNumber, err := accountInfo.SequenceNumber()
	if err != nil {
		return nil, nil, caperrors.NewPublicSystemError(fmt.Errorf("failed to parse account sequence number: %w", err), caperrors.Unavailable)
	}
	if sequenceNumber == 0 || *limit == 0 {
		zero := uint64(0)
		return &zero, &zero, nil
	}

	boundedLimit := min(*limit, sequenceNumber)
	boundedStart := sequenceNumber - boundedLimit
	fc.eng.Debugw("AccountTransactions: resolved latest transaction window",
		"address", address.String(),
		"sequenceNumber", sequenceNumber,
		"requestedLimit", *limit,
		"start", boundedStart,
		"limit", boundedLimit,
	)
	return &boundedStart, &boundedLimit, nil
}

func (fc *FakeAptosChain) WriteReport(
	ctx context.Context,
	_ commonCap.RequestMetadata,
	input *aptoscappb.WriteReportRequest,
) (*commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain WriteReport Started")
	fc.eng.Debugw("Aptos Chain WriteReport Input", "input", input)
	if input == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("writeReportRequest is nil"), caperrors.InvalidArgument)
	}
	if input.Report == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("report must not be nil"), caperrors.InvalidArgument)
	}
	if input.GasConfig == nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("gasConfig must not be nil"), caperrors.InvalidArgument)
	}
	if input.GasConfig.MaxGasAmount == 0 {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("gasConfig.maxGasAmount must be > 0"), caperrors.InvalidArgument)
	}
	if input.GasConfig.GasUnitPrice == 0 {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("gasConfig.gasUnitPrice must be > 0"), caperrors.InvalidArgument)
	}
	receiver, err := addressFromBytes(input.Receiver)
	if err != nil {
		return nil, caperrors.NewPublicUserError(fmt.Errorf("invalid receiver: %w", err), caperrors.InvalidArgument)
	}
	sigs := make([][]byte, len(input.Report.Sigs))
	for i, s := range input.Report.Sigs {
		if s == nil {
			return nil, caperrors.NewPublicUserError(fmt.Errorf("report.Sigs[%d] is nil", i), caperrors.InvalidArgument)
		}
		sigs[i] = s.Signature
	}
	if fc.dryRunWrites {
		return fc.writeReportDryRun(ctx, receiver, input.Report.RawReport, sigs, input.GasConfig)
	}
	return fc.writeReportBroadcast(ctx, receiver, input.Report.RawReport, sigs, input.GasConfig)
}

func (fc *FakeAptosChain) writeReportBroadcast(
	_ context.Context,
	receiver aptos.AccountAddress,
	rawReport []byte, sigs [][]byte,
	gas *aptoscappb.GasConfig,
) (*commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply], caperrors.Error) {
	maxGas := gas.MaxGasAmount
	unitPrice := gas.GasUnitPrice
	opts := &bind.TransactOpts{
		Signer:       fc.account,
		MaxGasAmount: &maxGas,
		GasUnitPrice: &unitPrice,
	}
	pending, err := fc.mockForwarder.Report(opts, receiver, rawReport, sigs)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("mock forwarder Report: %w", err), caperrors.Unavailable)
	}
	if pending == nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("mock forwarder Report: nil pending transaction"), caperrors.Internal)
	}
	fc.eng.Debugw("Aptos Chain WriteReport Submitted", "txHash", pending.Hash)
	final, err := fc.client.WaitForTransaction(pending.Hash)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("wait for tx: %w", err), caperrors.Unavailable)
	}
	return fc.writeReportReplyFromUserTx(final, pending.Hash), nil
}

func (fc *FakeAptosChain) writeReportReplyFromUserTx(
	final *api.UserTransaction, hash string,
) *commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply] {
	if final == nil {
		fc.eng.Infow("Aptos Chain WriteReport Failed", "txHash", hash, "reason", "nil final tx")
		h := hash
		return wrapWriteReportReply(&aptoscappb.WriteReportReply{TxStatus: aptoscappb.TxStatus_TX_STATUS_FATAL, TxHash: &h})
	}
	fee := final.GasUsed * final.GasUnitPrice
	if final.Success {
		fc.eng.Infow("Aptos Chain WriteReport Successful", "txHash", hash, "gasUsed", final.GasUsed, "fee", fee)
	} else {
		fc.eng.Infow("Aptos Chain WriteReport Failed", "txHash", hash, "gasUsed", final.GasUsed, "fee", fee, "vmStatus", final.VmStatus)
	}
	return wrapWriteReportReply(fc.buildWriteReportReply(hash, fee, final.Success, final.VmStatus))
}

// buildWriteReportReply builds a WriteReportReply for broadcast and dry-run
// paths. hash="" omits TxHash (dry-run has none).
func (fc *FakeAptosChain) buildWriteReportReply(hash string, fee uint64, success bool, vmStatus string) *aptoscappb.WriteReportReply {
	r := &aptoscappb.WriteReportReply{TransactionFee: &fee}
	if hash != "" {
		h := hash
		r.TxHash = &h
	}
	if success {
		recv := aptoscappb.ReceiverContractExecutionStatus_RECEIVER_CONTRACT_EXECUTION_STATUS_SUCCESS
		r.TxStatus = aptoscappb.TxStatus_TX_STATUS_SUCCESS
		r.ReceiverContractExecutionStatus = &recv
		return r
	}
	vm := vmStatus
	// Aptos proto enum lacks TX_STATUS_REVERTED (has FATAL/ABORTED/SUCCESS); EVM has
	// FATAL/REVERTED/SUCCESS. Receiver-vs-forwarder revert distinction is preserved via
	// ReceiverContractExecutionStatus only. Upstream proto change needed for top-level parity.
	r.TxStatus = aptoscappb.TxStatus_TX_STATUS_FATAL
	r.ErrorMessage = &vm
	r.ReceiverContractExecutionStatus = receiverContractExecutionStatusFromFailedVMStatus(vmStatus, fc.forwarderAddress, mockForwarderModuleName)
	return r
}

func wrapWriteReportReply(r *aptoscappb.WriteReportReply) *commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply] {
	return &commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply]{Response: r}
}

func (fc *FakeAptosChain) writeReportDryRun(
	_ context.Context,
	receiver aptos.AccountAddress,
	rawReport []byte, sigs [][]byte,
	gas *aptoscappb.GasConfig,
) (*commonCap.ResponseAndMetadata[*aptoscappb.WriteReportReply], caperrors.Error) {
	fc.eng.Infow("Aptos Chain WriteReport Dry-Run Enabled")
	modInfo, function, argTypes, args, err := fc.mockForwarder.Encoder().Report(receiver, rawReport, sigs)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("encode report: %w", err), caperrors.Internal)
	}
	ef := &aptos.EntryFunction{
		Module: aptos.ModuleId{
			Address: modInfo.Address,
			Name:    modInfo.ModuleName,
		},
		Function: function,
		ArgTypes: argTypes,
		Args:     args,
	}
	payload := aptos.TransactionPayload{Payload: ef}
	rawTxn, err := fc.client.BuildTransaction(
		fc.account.AccountAddress(),
		payload,
		aptos.MaxGasAmount(gas.MaxGasAmount),
		aptos.GasUnitPrice(gas.GasUnitPrice),
	)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("build tx: %w", err), caperrors.Unavailable)
	}
	if rawTxn == nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("build tx: nil raw transaction"), caperrors.Internal)
	}
	results, err := fc.client.SimulateTransaction(rawTxn, fc.account)
	if err != nil {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("simulate: %w", err), caperrors.Unavailable)
	}
	if len(results) == 0 {
		return nil, caperrors.NewPublicSystemError(fmt.Errorf("simulate: empty result"), caperrors.Internal)
	}
	r := results[0]
	fee := r.GasUsed * r.GasUnitPrice
	if r.Success {
		fc.eng.Infow("Aptos Chain WriteReport Dry-Run Successful", "gasUsed", r.GasUsed, "fee", fee)
	} else {
		fc.eng.Infow("Aptos Chain WriteReport Dry-Run Reverted", "gasUsed", r.GasUsed, "fee", fee, "vmStatus", r.VmStatus)
	}
	return wrapWriteReportReply(fc.buildWriteReportReply("", fee, r.Success, r.VmStatus)), nil
}
