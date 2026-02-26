package relayer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	aptosdk "github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	aptoscrypto "github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/types"
	typeaptos "github.com/smartcontractkit/chainlink-common/pkg/types/chains/aptos"
	"github.com/smartcontractkit/chainlink-common/pkg/types/core"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chain"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	crconfig "github.com/smartcontractkit/chainlink-aptos/relayer/chainreader/config"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainwriter"
	rutils "github.com/smartcontractkit/chainlink-aptos/relayer/utils"
	write_target "github.com/smartcontractkit/chainlink-aptos/relayer/write_target/aptos"
)

var _ types.Relayer = (*relayer)(nil) //nolint:staticcheck

type relayer struct {
	chain chain.Chain
	lggr  logger.Logger

	starter commonutils.StartStopOnce
	stopCh  services.StopChan
}

func NewRelayer(lggr logger.Logger, chain chain.Chain, capRegistry core.CapabilitiesRegistry) (*relayer, error) {
	ctx := context.TODO()

	if chain.Config().Workflow != nil {
		capability, err := write_target.NewAptosWriteTarget(ctx, chain, lggr)
		if err != nil {
			return nil, err
		}
		if err = capRegistry.Add(ctx, capability); err != nil {
			return nil, err
		}
	} else {
		lggr.Warn("No workflow config found, skipping write target creation")
	}

	return &relayer{
		chain:  chain,
		lggr:   lggr,
		stopCh: make(chan struct{}),
	}, nil
}

func (r *relayer) Name() string {
	return r.lggr.Name()
}

// Start starts the relayer respecting the given context.
func (r *relayer) Start(ctx context.Context) error {
	return r.starter.StartOnce("AptosRelayer", func() error {
		r.lggr.Debug("Starting")
		r.lggr.Debug("Starting chain")

		if r.chain == nil {
			return errors.New("Aptos unavailable")
		}

		var ms services.MultiStart
		return ms.Start(ctx, r.chain)
	})
}

// Close will close all open subservices
func (r *relayer) Close() error {
	return r.starter.StopOnce("AptosRelayer", func() error {
		r.lggr.Debug("Stopping")
		r.lggr.Debug("Stopping chain")

		close(r.stopCh)
		return services.CloseAll(r.chain)
	})
}

func (r *relayer) Ready() error {
	return r.chain.Ready()
}

func (r *relayer) Healthy() error { return nil }

func (r *relayer) HealthReport() map[string]error {
	return map[string]error{r.Name(): r.Healthy()}
}

func (r *relayer) NewContractWriter(ctx context.Context, configBytes []byte) (types.ContractWriter, error) {
	cfg := chainwriter.ChainWriterConfig{}
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshall chain writer config err: %s", err)
	}

	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	chainWriter := chainwriter.NewChainWriter(r.lggr, client, r.chain.TxManager(), cfg)
	return chainWriter, nil
}

func (r *relayer) NewContractReader(ctx context.Context, configBytes []byte) (types.ContractReader, error) {
	cfg := crconfig.ChainReaderConfig{}
	if err := json.Unmarshal(configBytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshall chain reader config err: %s", err)
	}

	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	chainReader := chainreader.NewChainReader(r.lggr, client, cfg, r.chain.DataSource(), r.chain.LogPoller())
	return chainReader, nil
}

func (r *relayer) NewConfigProvider(ctx context.Context, args types.RelayArgs) (types.ConfigProvider, error) {
	return nil, errors.New("ocr2 is not supported for aptos")
}

func (r *relayer) NewPluginProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.PluginProvider, error) {
	return nil, errors.New("plugin provider is not supported for aptos")
}

func (r *relayer) NewLLOProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.LLOProvider, error) {
	return nil, errors.New("data streams is not supported for aptos")
}

func (r *relayer) NewMedianProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.MedianProvider, error) {
	return nil, errors.New("ocr2 is not supported for aptos")
}

func (r *relayer) NewMercuryProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.MercuryProvider, error) {
	return nil, errors.New("mercury is not supported for aptos")
}

func (r *relayer) NewFunctionsProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.FunctionsProvider, error) {
	return nil, errors.New("functions are not supported for aptos")
}

func (r *relayer) NewAutomationProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.AutomationProvider, error) {
	return nil, errors.New("automation is not supported for aptos")
}

func (r *relayer) NewOCR3CapabilityProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.OCR3CapabilityProvider, error) {
	return nil, errors.New("ocr3 capability provider is not supported for aptos")
}

func (r *relayer) NewCCIPProvider(ctx context.Context, cargs types.CCIPProviderArgs) (types.CCIPProvider, error) {
	return nil, errors.New("ccip provider is not supported for aptos")
}

func (r *relayer) NewCCIPCommitProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.CCIPCommitProvider, error) {
	return nil, errors.New("ccip.commit is not supported for aptos")
}

func (r *relayer) NewCCIPExecProvider(ctx context.Context, rargs types.RelayArgs, pargs types.PluginArgs) (types.CCIPExecProvider, error) {
	return nil, errors.New("ccip.exec is not supported for aptos")
}

func (r *relayer) EVM() (types.EVMService, error) {
	return nil, errors.New("EVMService is not supported for aptos")
}

func (r *relayer) TON() (types.TONService, error) {
	return nil, errors.New("TONService is not supported for aptos")
}

func (r *relayer) Solana() (types.SolanaService, error) {
	return nil, errors.New("SolanaService is not supported for aptos")
}

func (r *relayer) Aptos() (types.AptosService, error) {
	return r, nil
}

func (r *relayer) Replay(ctx context.Context, fromBlock string, args map[string]any) error {
	return errors.ErrUnsupported
}

// ChainService interface
func (r *relayer) GetChainStatus(ctx context.Context) (types.ChainStatus, error) {
	return r.chain.GetChainStatus(ctx)
}

func (r *relayer) LatestHead(ctx context.Context) (types.Head, error) {
	return r.chain.LatestHead(ctx)
}

func (r *relayer) GetChainInfo(ctx context.Context) (types.ChainInfo, error) {
	return r.chain.GetChainInfo(ctx)
}

func (r *relayer) ListNodeStatuses(ctx context.Context, pageSize int32, pageToken string) (stats []types.NodeStatus, nextPageToken string, total int, err error) {
	return r.chain.ListNodeStatuses(ctx, pageSize, pageToken)
}

func (r *relayer) Transact(ctx context.Context, from, to string, amount *big.Int, balanceCheck bool) error {
	return r.chain.Transact(ctx, from, to, amount, balanceCheck)
}

func (r *relayer) AccountAPTBalance(ctx context.Context, req typeaptos.AccountAPTBalanceRequest) (*typeaptos.AccountAPTBalanceReply, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	balance, err := client.AccountAPTBalance(aptosdk.AccountAddress(req.Address))
	if err != nil {
		return nil, err
	}

	return &typeaptos.AccountAPTBalanceReply{Value: balance}, nil
}

func (r *relayer) LedgerVersion(ctx context.Context) (uint64, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return 0, fmt.Errorf("failed to get client: %w", err)
	}

	info, err := client.Info()
	if err != nil {
		return 0, fmt.Errorf("failed to fetch node info: %w", err)
	}

	return info.LedgerVersion(), nil
}

func (r *relayer) View(ctx context.Context, req typeaptos.ViewRequest) (*typeaptos.ViewReply, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	payload, err := toSDKViewPayload(req.Payload)
	if err != nil {
		return nil, err
	}

	var result []any
	if req.LedgerVersion != nil {
		result, err = client.View(payload, *req.LedgerVersion)
	} else {
		result, err = client.View(payload)
	}
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal view response: %w", err)
	}

	return &typeaptos.ViewReply{Data: data}, nil
}

func (r *relayer) EventsByHandle(ctx context.Context, req typeaptos.EventsByHandleRequest) (*typeaptos.EventsByHandleReply, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	events, err := client.EventsByHandle(aptosdk.AccountAddress(req.Account), req.EventHandle, req.FieldName, req.Start, req.Limit)
	if err != nil {
		return nil, err
	}

	out := &typeaptos.EventsByHandleReply{Events: make([]*typeaptos.Event, 0, len(events))}
	for _, e := range events {
		if e == nil {
			continue
		}

		ev := &typeaptos.Event{
			Version:        e.Version,
			Type:           e.Type,
			SequenceNumber: e.SequenceNumber,
		}
		if e.Guid != nil {
			var addr typeaptos.AccountAddress
			if e.Guid.AccountAddress != nil {
				copy(addr[:], e.Guid.AccountAddress[:])
			}
			ev.Guid = &typeaptos.GUID{
				CreationNumber: e.Guid.CreationNumber,
				AccountAddress: addr,
			}
		}
		if e.Data != nil {
			data, marshalErr := json.Marshal(e.Data)
			if marshalErr != nil {
				return nil, fmt.Errorf("failed to marshal event data: %w", marshalErr)
			}
			ev.Data = data
		}
		out.Events = append(out.Events, ev)
	}

	return out, nil
}

func (r *relayer) TransactionByHash(ctx context.Context, req typeaptos.TransactionByHashRequest) (*typeaptos.TransactionByHashReply, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	tx, err := client.TransactionByHash(req.Hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return &typeaptos.TransactionByHashReply{}, nil
	}

	converted, err := convertSDKTransaction(tx)
	if err != nil {
		return nil, err
	}
	return &typeaptos.TransactionByHashReply{Transaction: converted}, nil
}

func (r *relayer) SubmitTransaction(ctx context.Context, req typeaptos.SubmitTransactionRequest) (*typeaptos.SubmitTransactionReply, error) {
	cfg := r.chain.Config()
	if cfg.Workflow == nil || cfg.Workflow.PublicKey == "" {
		return nil, fmt.Errorf("workflow public key not configured")
	}

	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	var payload aptosdk.TransactionPayload
	if err := bcs.Deserialize(&payload, req.EncodedPayload); err != nil {
		return nil, fmt.Errorf("failed to decode transaction payload: %w", err)
	}

	publicKey, err := rutils.HexPublicKeyToEd25519PublicKey(cfg.Workflow.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid workflow public key: %w", err)
	}
	fromAddress := rutils.Ed25519PublicKeyToAddress(publicKey)

	accountInfo, err := client.Account(fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account info: %w", err)
	}
	sequenceNumber, err := accountInfo.SequenceNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to parse sequence number: %w", err)
	}

	chainID, err := client.GetChainId()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch chain id: %w", err)
	}

	info, err := client.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch node info: %w", err)
	}
	ledgerTimestamp := info.LedgerTimestamp()
	if ledgerTimestamp == 0 {
		return nil, fmt.Errorf("ledger timestamp is zero")
	}

	txCfg := cfg.TransactionManager
	expiration := (ledgerTimestamp / 1_000_000) + txCfg.TxExpirationSecs

	var maxGasAmount uint64
	var gasUnitPrice uint64
	if req.GasConfig != nil {
		maxGasAmount = req.GasConfig.MaxGasAmount
		gasUnitPrice = req.GasConfig.GasUnitPrice
	} else {
		gasInfo, gasErr := client.EstimateGasPrice()
		if gasErr != nil {
			return nil, fmt.Errorf("failed to estimate gas price: %w", gasErr)
		}
		maxGasAmount = txCfg.DefaultMaxGasAmount + txCfg.GasLimitOverhead
		gasUnitPrice = gasInfo.GasEstimate
	}

	rawTx := aptosdk.RawTransaction{
		Sender:                     fromAddress,
		SequenceNumber:             sequenceNumber,
		Payload:                    payload,
		MaxGasAmount:               maxGasAmount,
		GasUnitPrice:               gasUnitPrice,
		ExpirationTimestampSeconds: expiration,
		ChainId:                    chainID,
	}

	signedTx, signature, err := signRawTransaction(ctx, r.chain.KeyStore(), cfg.Workflow.PublicKey, publicKey, &rawTx)
	if err != nil {
		return nil, err
	}

	submitResponse, err := client.SubmitTransaction(signedTx)
	if err != nil {
		return nil, err
	}
	if submitResponse == nil || submitResponse.Hash == "" {
		return nil, fmt.Errorf("submit transaction returned empty hash")
	}

	return &typeaptos.SubmitTransactionReply{
		PendingTransaction: &typeaptos.PendingTransaction{
			Hash:                    submitResponse.Hash,
			Sender:                  typeaptos.AccountAddress(fromAddress),
			SequenceNumber:          sequenceNumber,
			MaxGasAmount:            maxGasAmount,
			GasUnitPrice:            gasUnitPrice,
			ExpirationTimestampSecs: expiration,
			Payload:                 req.EncodedPayload,
			Signature:               signature,
		},
	}, nil
}

func (r *relayer) AccountTransactions(ctx context.Context, req typeaptos.AccountTransactionsRequest) (*typeaptos.AccountTransactionsReply, error) {
	client, err := r.chain.GetClient()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	txs, err := client.AccountTransactions(aptosdk.AccountAddress(req.Address), req.Start, req.Limit)
	if err != nil {
		return nil, err
	}

	out := &typeaptos.AccountTransactionsReply{Transactions: make([]*typeaptos.Transaction, 0, len(txs))}
	for _, tx := range txs {
		if tx == nil {
			continue
		}
		asTxn := &aptosapi.Transaction{Type: tx.Type, Inner: tx.Inner}
		converted, convErr := convertSDKTransaction(asTxn)
		if convErr != nil {
			return nil, convErr
		}
		out.Transactions = append(out.Transactions, converted)
	}

	return out, nil
}

func convertSDKTransaction(tx *aptosapi.Transaction) (*typeaptos.Transaction, error) {
	if tx == nil {
		return nil, nil
	}

	var version *uint64
	if v := tx.Version(); v != nil {
		vv := *v
		version = &vv
	}

	var success *bool
	if s := tx.Success(); s != nil {
		ss := *s
		success = &ss
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	return &typeaptos.Transaction{
		Type:    typeaptos.TransactionVariant(tx.Type),
		Hash:    string(tx.Hash()),
		Version: version,
		Success: success,
		Data:    data,
	}, nil
}

func toSDKViewPayload(payload *typeaptos.ViewPayload) (*aptosdk.ViewPayload, error) {
	if payload == nil {
		return nil, fmt.Errorf("view payload is nil")
	}

	argTypes := make([]aptosdk.TypeTag, 0, len(payload.ArgTypes))
	for _, t := range payload.ArgTypes {
		converted, err := toSDKTypeTag(t)
		if err != nil {
			return nil, err
		}
		argTypes = append(argTypes, converted)
	}

	return &aptosdk.ViewPayload{
		Module: aptosdk.ModuleId{
			Address: aptosdk.AccountAddress(payload.Module.Address),
			Name:    payload.Module.Name,
		},
		Function: payload.Function,
		ArgTypes: argTypes,
		Args:     payload.Args,
	}, nil
}

func toSDKTypeTag(tag typeaptos.TypeTag) (aptosdk.TypeTag, error) {
	switch v := tag.Value.(type) {
	case typeaptos.BoolTag:
		return aptosdk.TypeTag{Value: &aptosdk.BoolTag{}}, nil
	case typeaptos.U8Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U8Tag{}}, nil
	case typeaptos.U16Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U16Tag{}}, nil
	case typeaptos.U32Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U32Tag{}}, nil
	case typeaptos.U64Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U64Tag{}}, nil
	case typeaptos.U128Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U128Tag{}}, nil
	case typeaptos.U256Tag:
		return aptosdk.TypeTag{Value: &aptosdk.U256Tag{}}, nil
	case typeaptos.AddressTag:
		return aptosdk.TypeTag{Value: &aptosdk.AddressTag{}}, nil
	case typeaptos.SignerTag:
		return aptosdk.TypeTag{Value: &aptosdk.SignerTag{}}, nil
	case typeaptos.VectorTag:
		inner, err := toSDKTypeTag(v.ElementType)
		if err != nil {
			return aptosdk.TypeTag{}, err
		}
		return aptosdk.TypeTag{Value: &aptosdk.VectorTag{TypeParam: inner}}, nil
	case typeaptos.StructTag:
		typeParams := make([]aptosdk.TypeTag, 0, len(v.TypeParams))
		for _, p := range v.TypeParams {
			inner, err := toSDKTypeTag(p)
			if err != nil {
				return aptosdk.TypeTag{}, err
			}
			typeParams = append(typeParams, inner)
		}
		return aptosdk.TypeTag{
			Value: &aptosdk.StructTag{
				Address:    aptosdk.AccountAddress(v.Address),
				Module:     v.Module,
				Name:       v.Name,
				TypeParams: typeParams,
			},
		}, nil
	case typeaptos.GenericTag:
		return aptosdk.TypeTag{Value: &aptosdk.GenericTag{Num: uint64(v.Index)}}, nil
	default:
		return aptosdk.TypeTag{}, fmt.Errorf("unsupported aptos type tag: %T", tag.Value)
	}
}

func signRawTransaction(
	ctx context.Context,
	ks core.Keystore,
	publicKeyHex string,
	publicKey ed25519.PublicKey,
	rawTx *aptosdk.RawTransaction,
) (*aptosdk.SignedTransaction, []byte, error) {
	signingMessage, err := rawTx.SigningMessage()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signing message: %w", err)
	}

	signature, err := ks.Sign(ctx, publicKeyHex, signingMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	edSig := aptoscrypto.Ed25519Signature{}
	if err := edSig.FromBytes(signature); err != nil {
		return nil, nil, fmt.Errorf("failed to decode ed25519 signature: %w", err)
	}

	authenticator := &aptoscrypto.AccountAuthenticator{
		Variant: aptoscrypto.AccountAuthenticatorEd25519,
		Auth: &aptoscrypto.Ed25519Authenticator{
			PubKey: &aptoscrypto.Ed25519PublicKey{Inner: publicKey},
			Sig:    &edSig,
		},
	}

	signedTx, err := rawTx.SignedTransactionWithAuthenticator(authenticator)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build signed transaction: %w", err)
	}

	return signedTx, signature, nil
}
