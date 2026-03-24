package relayer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	aptos_sdk "github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	commonaptos "github.com/smartcontractkit/chainlink-common/pkg/types/chains/aptos"
	"github.com/smartcontractkit/chainlink-common/pkg/utils/retry"
)

type aptosService struct {
	commontypes.UnimplementedAptosService
	chain  chain.Chain
	logger logger.Logger
}

func (s *aptosService) LedgerVersion(ctx context.Context) (uint64, error) {
	client, err := s.chain.GetClient()
	if err != nil {
		return 0, fmt.Errorf("failed to get client: %w", err)
	}

	info, err := client.Info()
	if err != nil {
		return 0, fmt.Errorf("failed to get latest ledger version: %w", err)
	}

	return info.LedgerVersion(), nil
}

func (s *aptosService) AccountAPTBalance(ctx context.Context, req commonaptos.AccountAPTBalanceRequest) (*commonaptos.AccountAPTBalanceReply, error) {
	client, err := s.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	sdkAddr := aptos_sdk.AccountAddress(req.Address[:])
	reply, err := client.AccountAPTBalance(sdkAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get account APT balance: %w", err)
	}
	return &commonaptos.AccountAPTBalanceReply{Value: reply}, nil
}

func (s *aptosService) View(ctx context.Context, req commonaptos.ViewRequest) (*commonaptos.ViewReply, error) {
	if req.Payload == nil {
		s.logger.Errorw("View: payload is nil")
		return nil, fmt.Errorf("view payload is required")
	}
	s.logger.Infow("View: request details",
		"moduleAddress", fmt.Sprintf("0x%x", req.Payload.Module.Address),
		"moduleName", req.Payload.Module.Name,
		"function", req.Payload.Function,
		"numArgTypes", len(req.Payload.ArgTypes),
		"numArgs", len(req.Payload.Args),
		"args", req.Payload.Args,
	)

	client, err := s.chain.GetClient()
	if err != nil {
		s.logger.Errorw("View: failed to get client", "error", err)
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	sdkPayload := &aptos_sdk.ViewPayload{
		Module: aptos_sdk.ModuleId{
			Address: aptos_sdk.AccountAddress(req.Payload.Module.Address),
			Name:    req.Payload.Module.Name,
		},
		Function: req.Payload.Function,
		ArgTypes: convertTypeTagsToSDK(req.Payload.ArgTypes),
		Args:     req.Payload.Args,
	}

	var result []any
	if req.LedgerVersion != nil {
		result, err = client.View(sdkPayload, *req.LedgerVersion)
	} else {
		result, err = client.View(sdkPayload)
	}
	if err != nil {
		s.logger.Errorw("View: view function call failed", "error", err)
		return nil, fmt.Errorf("failed to call view function: %w", err)
	}

	data, err := json.Marshal(result)
	if err != nil {
		s.logger.Errorw("View: failed to marshal view result", "error", err)
		return nil, fmt.Errorf("failed to marshal view result: %w", err)
	}

	s.logger.Infow("View: success", "responseLen", len(data), "responseData", string(data))
	return &commonaptos.ViewReply{Data: data}, nil
}

func (s *aptosService) TransactionByHash(ctx context.Context, req commonaptos.TransactionByHashRequest) (*commonaptos.TransactionByHashReply, error) {
	client, err := s.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	tx, err := client.TransactionByHash(req.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction by hash: %w", err)
	}

	data, err := json.Marshal(tx.Inner)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction data: %w", err)
	}

	return &commonaptos.TransactionByHashReply{
		Transaction: &commonaptos.Transaction{
			Type:    commonaptos.TransactionVariant(tx.Type),
			Hash:    string(tx.Hash()),
			Version: tx.Version(),
			Success: tx.Success(),
			Data:    data,
		},
	}, nil
}

func (s *aptosService) AccountTransactions(ctx context.Context, req commonaptos.AccountTransactionsRequest) (*commonaptos.AccountTransactionsReply, error) {
	s.logger.Infow("AccountTransactions: called",
		"address", fmt.Sprintf("0x%x", req.Address),
		"hasStart", req.Start != nil,
		"hasLimit", req.Limit != nil,
	)

	client, err := s.chain.GetClient()
	if err != nil {
		s.logger.Errorw("AccountTransactions: failed to get client", "error", err)
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	sdkAddr := aptos_sdk.AccountAddress(req.Address[:])
	txns, err := client.AccountTransactions(sdkAddr, req.Start, req.Limit)
	if err != nil {
		s.logger.Errorw("AccountTransactions: failed to get transactions", "address", sdkAddr.String(), "error", err)
		return nil, fmt.Errorf("failed to get account transactions: %w", err)
	}

	s.logger.Infow("AccountTransactions: fetched", "address", sdkAddr.String(), "count", len(txns))

	result := make([]*commonaptos.Transaction, 0, len(txns))
	for _, tx := range txns {
		data, err := json.Marshal(tx.Inner)
		if err != nil {
			s.logger.Errorw("AccountTransactions: failed to marshal tx", "hash", string(tx.Hash()), "error", err)
			return nil, fmt.Errorf("failed to marshal transaction data: %w", err)
		}
		version := tx.Version()
		success := tx.Success()
		result = append(result, &commonaptos.Transaction{
			Type:    commonaptos.TransactionVariant(tx.Type),
			Hash:    string(tx.Hash()),
			Version: &version,
			Success: &success,
			Data:    data,
		})
	}

	s.logger.Infow("AccountTransactions: returning", "address", sdkAddr.String(), "txCount", len(result))
	return &commonaptos.AccountTransactionsReply{Transactions: result}, nil
}

func (s *aptosService) SubmitTransaction(ctx context.Context, req commonaptos.SubmitTransactionRequest) (*commonaptos.SubmitTransactionReply, error) {
	s.logger.Infow("SubmitTransaction: called",
		"encodedPayloadLen", len(req.EncodedPayload),
		"hasGasConfig", req.GasConfig != nil,
		"moduleAddress", fmt.Sprintf("%x", req.ReceiverModuleID.Address),
		"moduleName", req.ReceiverModuleID.Name,
	)

	// Deserialize the BCS-encoded TransactionPayload (containing an EntryFunction)
	var txPayload aptos_sdk.TransactionPayload
	if err := bcs.Deserialize(&txPayload, req.EncodedPayload); err != nil {
		s.logger.Errorw("SubmitTransaction: failed to deserialize payload", "error", err)
		return nil, fmt.Errorf("failed to deserialize transaction payload: %w", err)
	}

	entryFn, ok := txPayload.Payload.(*aptos_sdk.EntryFunction)
	if !ok {
		s.logger.Errorw("SubmitTransaction: unexpected payload type", "type", fmt.Sprintf("%T", txPayload.Payload))
		return nil, fmt.Errorf("expected EntryFunction payload, got %T", txPayload.Payload)
	}
	s.logger.Infow("SubmitTransaction: deserialized entry function",
		"module", entryFn.Module.Address.String()+"::"+entryFn.Module.Name,
		"function", entryFn.Function,
	)

	var gasLimit *big.Int
	if req.GasConfig != nil {
		gasLimit = big.NewInt(int64(req.GasConfig.MaxGasAmount))
	}
	accounts, err := s.chain.KeyStore().Accounts(ctx)
	if err != nil {
		s.logger.Errorw("SubmitTransaction: failed to get accounts", "error", err)
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}
	s.logger.Infow("SubmitTransaction: accounts retrieved", "numAccounts", len(accounts))

	// Find account with highest balance
	publicKey, err := s.getAccountWithHighestBalance(ctx, accounts)
	if err != nil {
		s.logger.Errorw("SubmitTransaction: failed to get account with highest balance", "error", err)
		return nil, fmt.Errorf("failed to determine account for SubmitTransaction: %w", err)
	}
	s.logger.Infow("SubmitTransaction: selected account", "publicKey", publicKey)

	txID := uuid.New().String()
	s.logger.Infow("SubmitTransaction: enqueueing to TxManager", "txID", txID)
	_, enqueueErr := s.chain.TxManager().EnqueueWithEntryFunction(
		txID,
		&commontypes.TxMeta{
			GasLimit: gasLimit,
		},
		publicKey,
		entryFn,
		true, // simulateTx
		// TODO: add expected simulation failures to save gas on reported transmissions
	)
	if enqueueErr != nil {
		s.logger.Errorw("SubmitTransaction: EnqueueWithEntryFunction failed", "txID", txID, "error", enqueueErr)
		return nil, fmt.Errorf("failed to enqueue transaction: %w", enqueueErr)
	}
	s.logger.Infow("SubmitTransaction: enqueued successfully", "txID", txID)

	// TODO: dont use txmgr config, create and use workflow/cre config PLEX-2598
	maximumWaitTime := time.Duration(*s.chain.Config().TransactionManager.TxExpirationSecs) * time.Second
	s.logger.Infow("SubmitTransaction: polling for status", "txID", txID, "maximumWaitTime", maximumWaitTime)

	retryCtx, cancel := context.WithTimeout(ctx, maximumWaitTime)
	defer cancel()
	txStatus, err := retry.Do(retryCtx, s.logger, func(_ context.Context) (commonaptos.TransactionStatus, error) {
		txStatus, txStatusErr := s.chain.TxManager().GetStatus(txID)
		if txStatusErr != nil {
			s.logger.Errorw("SubmitTransaction: GetStatus error", "txID", txID, "error", txStatusErr)
			return commonaptos.TxFatal, txStatusErr
		}
		s.logger.Debugw("SubmitTransaction: GetStatus poll", "txID", txID, "status", txStatus)
		switch txStatus {
		case commontypes.Fatal, commontypes.Failed:
			s.logger.Infow("SubmitTransaction: terminal failure from TxManager", "txID", txID, "status", txStatus)
			return commonaptos.TxFatal, nil
		case commontypes.Finalized:
			s.logger.Infow("SubmitTransaction: finalized, checking result", "txID", txID)
			txResult, resultErr := s.chain.TxManager().GetTransactionResult(txID)
			if resultErr != nil {
				s.logger.Errorw("SubmitTransaction: GetTransactionResult failed for finalized tx", "txID", txID, "error", resultErr)
				return commonaptos.TxFatal, resultErr
			}
			s.logger.Infow("SubmitTransaction: finalized result", "txID", txID, "vmStatus", txResult.VmStatus, "txHash", txResult.TxHash)
			if txResult.VmStatus != "" {
				s.logger.Warnw("SubmitTransaction: finalized but VM reverted", "txID", txID, "vmStatus", txResult.VmStatus)
				return commonaptos.TxReverted, nil
			}
			return commonaptos.TxSuccess, nil
		case commontypes.Unconfirmed:
			s.logger.Debugw("SubmitTransaction: still unconfirmed (broadcast but not yet confirmed on-chain)", "txID", txID)
			return commonaptos.TxFatal, fmt.Errorf("tx still unconfirmed (broadcast, awaiting on-chain confirmation) for tx with ID %s", txID)
		case commontypes.Pending, commontypes.Unknown:
			s.logger.Debugw("SubmitTransaction: still pending/unknown, will retry", "txID", txID, "status", txStatus)
			return commonaptos.TxFatal, fmt.Errorf("tx still in state pending or unknown, tx status is %d for tx with ID %s", txStatus, txID)
		default:
			s.logger.Warnw("SubmitTransaction: unexpected status", "txID", txID, "status", txStatus)
			return commonaptos.TxFatal, fmt.Errorf("unexpected transaction status %d for tx with ID %s", txStatus, txID)
		}
	})

	if err != nil {
		s.logger.Errorw("SubmitTransaction: failed getting transaction status", "txID", txID, "error", err)
		return &commonaptos.SubmitTransactionReply{
			TxStatus:         commonaptos.TxFatal,
			TxIdempotencyKey: txID,
		}, fmt.Errorf("failed getting transaction status for txID %s: %w", txID, err)
	}

	s.logger.Infow("SubmitTransaction: final status", "txID", txID, "txStatus", txStatus)

	txResult, resultErr := s.chain.TxManager().GetTransactionResult(txID)
	if resultErr != nil {
		s.logger.Errorw("SubmitTransaction: failed to get transaction result", "txID", txID, "error", resultErr)
		return &commonaptos.SubmitTransactionReply{
			TxStatus:         commonaptos.TxFatal,
			TxIdempotencyKey: txID,
		}, fmt.Errorf("failed getting transaction result for txID %s: %w", txID, resultErr)
	}

	s.logger.Infow("SubmitTransaction: returning result", "txID", txID, "txStatus", txStatus, "txHash", txResult.TxHash, "vmStatus", txResult.VmStatus)
	return &commonaptos.SubmitTransactionReply{
		TxStatus:         txStatus,
		TxHash:           txResult.TxHash,
		TxIdempotencyKey: txID,
	}, nil
}

// getAccountWithHighestBalance returns the public key of the account with the highest APT balance.
func (s *aptosService) getAccountWithHighestBalance(ctx context.Context, accounts []string) (string, error) {
	if len(accounts) == 0 {
		return "", errors.New("no accounts provided")
	}
	if len(accounts) == 1 {
		s.logger.Debugw("getAccountWithHighestBalance: only one enabled account for chain", "account", accounts[0])
		return accounts[0], nil
	}

	client, err := s.chain.GetClient()
	if err != nil {
		return "", fmt.Errorf("failed to get client: %w", err)
	}

	var highestBalance uint64
	var selectedAccount string
	var foundAny bool

	for _, account := range accounts {
		addr, err := utils.HexPublicKeyToAddress(account)
		if err != nil {
			s.logger.Warnw("getAccountWithHighestBalance: failed to convert public key to address, skipping", "account", account, "error", err)
			continue
		}

		balance, err := client.AccountAPTBalance(addr)
		if err != nil {
			s.logger.Warnw("getAccountWithHighestBalance: failed to get balance for account, skipping", "account", account, "error", err)
			continue
		}

		if !foundAny || balance > highestBalance {
			highestBalance = balance
			selectedAccount = account
			foundAny = true
		}
	}

	if !foundAny {
		// Fallback to first account if all balance queries failed
		return accounts[0], nil
	}

	s.logger.Debugw("getAccountWithHighestBalance: selected account",
		"account", selectedAccount,
		"balance", highestBalance,
		"totalAccounts", len(accounts))

	return selectedAccount, nil
}

// convertTypeTagsToSDK converts common TypeTags to SDK TypeTags.
func convertTypeTagsToSDK(tags []commonaptos.TypeTag) []aptos_sdk.TypeTag {
	out := make([]aptos_sdk.TypeTag, len(tags))
	for i, tag := range tags {
		out[i] = aptos_sdk.TypeTag{Value: convertTypeTagImplToSDK(tag.Value)}
	}
	return out
}

func convertTypeTagImplToSDK(impl commonaptos.TypeTagImpl) aptos_sdk.TypeTagImpl {
	switch v := impl.(type) {
	case commonaptos.BoolTag:
		return &aptos_sdk.BoolTag{}
	case commonaptos.U8Tag:
		return &aptos_sdk.U8Tag{}
	case commonaptos.U16Tag:
		return &aptos_sdk.U16Tag{}
	case commonaptos.U32Tag:
		return &aptos_sdk.U32Tag{}
	case commonaptos.U64Tag:
		return &aptos_sdk.U64Tag{}
	case commonaptos.U128Tag:
		return &aptos_sdk.U128Tag{}
	case commonaptos.U256Tag:
		return &aptos_sdk.U256Tag{}
	case commonaptos.AddressTag:
		return &aptos_sdk.AddressTag{}
	case commonaptos.SignerTag:
		return &aptos_sdk.SignerTag{}
	case commonaptos.VectorTag:
		return &aptos_sdk.VectorTag{
			TypeParam: aptos_sdk.TypeTag{Value: convertTypeTagImplToSDK(v.ElementType.Value)},
		}
	case commonaptos.StructTag:
		typeParams := make([]aptos_sdk.TypeTag, len(v.TypeParams))
		for i, tp := range v.TypeParams {
			typeParams[i] = aptos_sdk.TypeTag{Value: convertTypeTagImplToSDK(tp.Value)}
		}
		return &aptos_sdk.StructTag{
			Address:    aptos_sdk.AccountAddress(v.Address),
			Module:     v.Module,
			Name:       v.Name,
			TypeParams: typeParams,
		}
	case commonaptos.GenericTag:
		return &aptos_sdk.GenericTag{Num: uint64(v.Index)}
	default:
		return nil
	}
}
