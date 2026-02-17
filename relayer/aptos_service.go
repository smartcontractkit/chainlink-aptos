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

	// Get sender info from workflow config
	wfCfg := s.chain.Config().Workflow
	if wfCfg == nil {
		return nil, fmt.Errorf("workflow config is required for SubmitTransaction")
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

	// Poll TxManager for status until terminal
	var txStatus commontypes.TransactionStatus
	for {
		txStatus, err = s.chain.TxManager().GetStatus(txID)
		if err != nil {
			return nil, fmt.Errorf("failed to get transaction status: %w", err)
		}

		switch txStatus {
		case commontypes.Finalized:
			return &commonaptos.SubmitTransactionReply{
				PendingTransaction: &commonaptos.PendingTransaction{
					Hash: txID,
				},
			}, nil
		case commontypes.Failed, commontypes.Fatal:
			return nil, fmt.Errorf("transaction failed with status: %v", txStatus)
		case commontypes.Pending, commontypes.Unknown, commontypes.Unconfirmed:
			// still in progress, wait and retry
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled while waiting for transaction: %w", ctx.Err())
			case <-time.After(500 * time.Millisecond):
				continue
			}
		default:
			return nil, fmt.Errorf("unexpected transaction status: %v", txStatus)
		}
	}
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
