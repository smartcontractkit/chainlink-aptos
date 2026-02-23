package relayer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	aptosgosdk "github.com/aptos-labs/aptos-go-sdk"
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

func (s *aptosService) AccountAPTBalance(ctx context.Context, req commonaptos.AccountAPTBalanceRequest) (*commonaptos.AccountAPTBalanceReply, error) {
	client, err := s.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}
	sdkAddr := aptosgosdk.AccountAddress(req.Address[:])
	reply, err := client.AccountAPTBalance(sdkAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get account APT balance: %w", err)
	}
	return &commonaptos.AccountAPTBalanceReply{Value: reply}, nil
}

func (s *aptosService) View(ctx context.Context, req commonaptos.ViewRequest) (*commonaptos.ViewReply, error) {
	if req.Payload == nil {
		return nil, fmt.Errorf("view payload is required")
	}

	client, err := s.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	sdkPayload := &aptosgosdk.ViewPayload{
		Module: aptosgosdk.ModuleId{
			Address: aptosgosdk.AccountAddress(req.Payload.Module.Address),
			Name:    req.Payload.Module.Name,
		},
		Function: req.Payload.Function,
		ArgTypes: convertTypeTagsToSDK(req.Payload.ArgTypes),
		Args:     req.Payload.Args,
	}

	result, err := client.View(sdkPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to call view function: %w", err)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal view result: %w", err)
	}

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

func (s *aptosService) SubmitTransaction(ctx context.Context, req commonaptos.SubmitTransactionRequest) (*commonaptos.SubmitTransactionReply, error) {
	// Deserialize the BCS-encoded TransactionPayload (containing an EntryFunction)
	var txPayload aptosgosdk.TransactionPayload
	if err := bcs.Deserialize(&txPayload, req.EncodedPayload); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction payload: %w", err)
	}

	entryFn, ok := txPayload.Payload.(*aptosgosdk.EntryFunction)
	if !ok {
		return nil, fmt.Errorf("expected EntryFunction payload, got %T", txPayload.Payload)
	}

	gasLimit := big.NewInt(int64(req.GasConfig.MaxGasAmount))
	accounts, err := s.chain.KeyStore().Accounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts: %w", err)
	}

	if len(accounts) == 0 {
		return nil, errors.New("no enabled accounts available")
	}

	// Find account with highest balance
	publicKey, err := s.getAccountWithHighestBalance(ctx, accounts)
	if err != nil {
		return nil, fmt.Errorf("failed to determine account for SubmitTransaction: %w", err)
	}
	txID := uuid.New().String()
	err = s.chain.TxManager().EnqueueCRE(
		txID,
		&commontypes.TxMeta{
			GasLimit: gasLimit,
		},
		publicKey,
		entryFn,
		true, // simulateTx
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enqueue transaction: %w", err)
	}
	// TODO: dont use txmgr config, create and use workflow/cre config
	maximumWaitTime := time.Duration(s.chain.Config().TransactionManager.TxExpirationSecs) * time.Second

	retryCtx, cancel := context.WithTimeout(ctx, maximumWaitTime)
	defer cancel()
	txStatus, err := retry.Do(retryCtx, s.logger, func(ctx context.Context) (commonaptos.TransactionStatus, error) {
		txStatus, txStatusErr := s.chain.TxManager().GetStatus(txID)
		if txStatusErr != nil {
			return commonaptos.TxFatal, txStatusErr
		}
		switch txStatus {
		case commontypes.Fatal, commontypes.Failed:
			return commonaptos.TxFatal, nil
		case commontypes.Unconfirmed, commontypes.Finalized:
			return commonaptos.TxSuccess, nil
		case commontypes.Pending, commontypes.Unknown:
			return commonaptos.TxFatal, fmt.Errorf("tx still in state pending or unknown, tx status is %d for tx with ID %s", txStatus, txID)
		default:
			return commonaptos.TxFatal, fmt.Errorf("unexpected transaction status %d for tx with ID %s", txStatus, txID)
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed getting transaction status: %w", err)
	}

	if txStatus == commonaptos.TxFatal {
		return &commonaptos.SubmitTransactionReply{
			TxStatus:         commonaptos.TxFatal,
			TxIdempotencyKey: txID,
		}, nil
	} else {
		return &commonaptos.SubmitTransactionReply{
			TxStatus:         commonaptos.TxSuccess,
			TxIdempotencyKey: txID,
		}, nil
	}
	// TODO:
	// get tx hash
	// make write report get tx by hash and check for success or revert reason
	// but then we also need to poll for transmission info because some other node might have done a success
	// so we need to go through all possible cases and then figure out how to handle retries

	/*
			receipt, err := retry.Do(retryContext, e.logger, func(ctx context.Context) (*evmtxmgr.ChainReceipt, error) {
			receipt, receiptErr := e.chain.TxManager().GetTransactionReceipt(ctx, txID)
			if receiptErr != nil {
				return nil, fmt.Errorf("failed to get TX receipt for tx with ID %s: %w", txID, receiptErr)
			}
			if receipt == nil {
				return nil, fmt.Errorf("receipt was nil for TX with ID %s", txID)
			}
			return receipt, nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed getting transaction receipt. %w", err)
		}

		return &evm.TransactionResult{
			TxStatus:         evm.TxSuccess,
			TxHash:           (*receipt).GetTxHash(),
			TxIdempotencyKey: txID,
		}, nil
	*/
}

// getAccountWithHighestBalance returns the public key of the account with the highest APT balance.
func (s *aptosService) getAccountWithHighestBalance(ctx context.Context, accounts []string) (string, error) {
	if len(accounts) == 0 {
		return "", errors.New("no accounts provided")
	}
	if len(accounts) == 1 {
		s.logger.Debugw("only one enabled account for chain", "account", accounts[0])
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
			s.logger.Warnw("failed to convert public key to address, skipping", "account", account, "error", err)
			continue
		}

		balance, err := client.AccountAPTBalance(addr)
		if err != nil {
			s.logger.Warnw("failed to get balance for account, skipping", "account", account, "address", addr.String(), "error", err)
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

	s.logger.Debugw("selected account with highest balance for chain",
		"account", selectedAccount,
		"balance", highestBalance,
		"totalAccounts", len(accounts))

	return selectedAccount, nil
}

// convertTypeTagsToSDK converts common TypeTags to SDK TypeTags.
func convertTypeTagsToSDK(tags []commonaptos.TypeTag) []aptosgosdk.TypeTag {
	out := make([]aptosgosdk.TypeTag, len(tags))
	for i, tag := range tags {
		out[i] = aptosgosdk.TypeTag{Value: convertTypeTagImplToSDK(tag.Value)}
	}
	return out
}

func convertTypeTagImplToSDK(impl commonaptos.TypeTagImpl) aptosgosdk.TypeTagImpl {
	switch v := impl.(type) {
	case commonaptos.BoolTag:
		return &aptosgosdk.BoolTag{}
	case commonaptos.U8Tag:
		return &aptosgosdk.U8Tag{}
	case commonaptos.U16Tag:
		return &aptosgosdk.U16Tag{}
	case commonaptos.U32Tag:
		return &aptosgosdk.U32Tag{}
	case commonaptos.U64Tag:
		return &aptosgosdk.U64Tag{}
	case commonaptos.U128Tag:
		return &aptosgosdk.U128Tag{}
	case commonaptos.U256Tag:
		return &aptosgosdk.U256Tag{}
	case commonaptos.AddressTag:
		return &aptosgosdk.AddressTag{}
	case commonaptos.SignerTag:
		return &aptosgosdk.SignerTag{}
	case commonaptos.VectorTag:
		return &aptosgosdk.VectorTag{
			TypeParam: aptosgosdk.TypeTag{Value: convertTypeTagImplToSDK(v.ElementType.Value)},
		}
	case commonaptos.StructTag:
		typeParams := make([]aptosgosdk.TypeTag, len(v.TypeParams))
		for i, tp := range v.TypeParams {
			typeParams[i] = aptosgosdk.TypeTag{Value: convertTypeTagImplToSDK(tp.Value)}
		}
		return &aptosgosdk.StructTag{
			Address:    aptosgosdk.AccountAddress(v.Address),
			Module:     v.Module,
			Name:       v.Name,
			TypeParams: typeParams,
		}
	case commonaptos.GenericTag:
		return &aptosgosdk.GenericTag{Num: uint64(v.Index)}
	default:
		return nil
	}
}
