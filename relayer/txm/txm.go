package txm

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"
	aptoscrypto "github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/google/uuid"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	commonutils "github.com/smartcontractkit/chainlink-common/pkg/utils"

	"github.com/smartcontractkit/chainlink-aptos/relayer/utils"
)

var _ services.Service = &AptosTxm{}

type AptosTxm struct {
	baseLogger logger.Logger
	keystore   loop.Keystore
	config     Config
	chainID    string
	metrics    *aptosTxmMetrics

	transactions              map[string]*AptosTx
	transactionsLock          sync.RWMutex
	transactionsLastPruneTime uint64

	broadcastChan chan string
	accountStore  *AccountStore
	starter       commonutils.StartStopOnce
	done          sync.WaitGroup
	stop          chan struct{}

	getClient func() (aptos.AptosRpcClient, error)
}

// TODO: Config input is not validated for sanity
func New(lgr logger.Logger, keystore loop.Keystore, config Config, getClient func() (aptos.AptosRpcClient, error), chainID string) (*AptosTxm, error) {
	metrics, err := newAptosTxmMetrics(chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	return &AptosTxm{
		baseLogger: logger.Named(lgr, "AptosTxm"),
		keystore:   keystore,
		config:     config,
		chainID:    chainID,
		metrics:    metrics,
		getClient:  getClient,

		transactions:              map[string]*AptosTx{},
		transactionsLastPruneTime: getTimestampSecs(),

		broadcastChan: make(chan string, *config.BroadcastChanSize),
		accountStore:  NewAccountStore(),
		stop:          make(chan struct{}),
	}, nil
}

func (a *AptosTxm) Name() string {
	return a.baseLogger.Name()
}

func (a *AptosTxm) Ready() error {
	return a.starter.Ready()
}

func (a *AptosTxm) HealthReport() map[string]error {
	return map[string]error{a.Name(): a.starter.Healthy()}
}

func (a *AptosTxm) Start(ctx context.Context) error {
	return a.starter.StartOnce(a.Name(), func() error {
		a.done.Add(2)
		go a.broadcastLoop()
		go a.confirmLoop()
		return nil
	})
}

func (a *AptosTxm) Close() error {
	return a.starter.StopOnce(a.Name(), func() error {
		close(a.stop)
		a.done.Wait()
		close(a.broadcastChan)
		return nil
	})
}

func (a *AptosTxm) Enqueue(transactionID string, txMetadata *commontypes.TxMeta, fromAddress, publicKey, function string, typeArgs []string, paramTypes []string, paramValues []any, simulateTx bool, expectedSimulationFailures ...ExpectedSimulationFailureRule) error {
	if transactionID == "" {
		transactionID = uuid.New().String()
	} else {
		a.transactionsLock.Lock()
		_, transactionExists := a.transactions[transactionID]
		a.transactionsLock.Unlock()
		if transactionExists {
			return errors.New("transaction already exists")
		}
	}

	ed25519PublicKey, err := utils.HexPublicKeyToEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %+w", err)
	}

	if fromAddress == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		acc := utils.Ed25519PublicKeyToAddress(ed25519PublicKey)
		fromAddress = acc.String()
	}

	functionTokens := strings.Split(function, "::")
	if len(functionTokens) != 3 {
		return fmt.Errorf("unexpected function name, expected 3 tokens, got %d", len(functionTokens))
	}
	if len(paramTypes) != len(paramValues) {
		return fmt.Errorf("length of param types and param values do not match")
	}

	contractAddress := functionTokens[0]
	moduleName := functionTokens[1]
	functionName := functionTokens[2]

	typeTags := []aptos.TypeTag{}
	for _, typeArg := range typeArgs {
		typeTag, err := CreateTypeTag(typeArg)
		if err != nil {
			return fmt.Errorf("failed to parse type argument %s: %+w", typeArg, err)
		}
		typeTags = append(typeTags, typeTag)
	}

	bcsValues := [][]byte{}

	for i := 0; i < len(paramTypes); i++ {
		typeName := paramTypes[i]
		typeValue := paramValues[i]

		typeTag, err := CreateTypeTag(typeName)
		if err != nil {
			return fmt.Errorf("failed to parse param type %s: %+w", typeName, err)
		}

		bcsValue, err := CreateBcsValue(typeTag, typeValue)
		if err != nil {
			return fmt.Errorf("failed to serialize param value %+v (type %T) using type tag %s: %+w", typeValue, typeValue, typeTag.String(), err)
		}

		bcsValues = append(bcsValues, bcsValue)
	}

	fromAccountAddress := &aptos.AccountAddress{}
	err = fromAccountAddress.ParseStringRelaxed(fromAddress)
	if err != nil {
		return fmt.Errorf("failed to parse from address: %+w", err)
	}

	contractAccountAddress := &aptos.AccountAddress{}
	err = contractAccountAddress.ParseStringRelaxed(contractAddress)
	if err != nil {
		return fmt.Errorf("failed to parse contract address: %+w", err)
	}

	tx := &AptosTx{
		ID:                             transactionID,
		Metadata:                       txMetadata,
		Timestamp:                      getTimestampSecs(),
		FromAddress:                    *fromAccountAddress,
		PublicKey:                      ed25519PublicKey,
		ContractAddress:                *contractAccountAddress,
		ModuleName:                     moduleName,
		FunctionName:                   functionName,
		TypeTags:                       typeTags,
		BcsValues:                      bcsValues,
		Status:                         commontypes.Pending,
		Simulate:                       simulateTx,
		ExpectedSimulationFailureRules: slices.Clone(expectedSimulationFailures),
	}

	return a.enqueueTransaction(tx)
}

// EnqueueWithEntryFunction is like Enqueue but accepts a deserialized EntryFunction directly,
// skipping the string-based function parsing and BCS serialisation of parameters.
// The EntryFunction already contains the module, function name, type tags, and
// pre-encoded BCS args.
func (a *AptosTxm) EnqueueWithEntryFunction(transactionID string, txMetadata *commontypes.TxMeta, publicKey string, entryFunction *aptos.EntryFunction, simulateTx bool) (string, error) {
	if entryFunction == nil {
		return "", errors.New("entry function is required")
	}

	if transactionID == "" {
		transactionID = uuid.New().String()
	} else {
		a.transactionsLock.Lock()
		_, transactionExists := a.transactions[transactionID]
		a.transactionsLock.Unlock()
		if transactionExists {
			return "", errors.New("transaction already exists")
		}
	}

	ed25519PublicKey, err := utils.HexPublicKeyToEd25519PublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to convert public key: %+w", err)
	}

	acc := utils.Ed25519PublicKeyToAddress(ed25519PublicKey)
	fromAccountAddress := aptos.AccountAddress(acc)

	tx := &AptosTx{
		ID:              transactionID,
		Metadata:        txMetadata,
		Timestamp:       getTimestampSecs(),
		FromAddress:     fromAccountAddress,
		PublicKey:       ed25519PublicKey,
		ContractAddress: entryFunction.Module.Address,
		ModuleName:      entryFunction.Module.Name,
		FunctionName:    entryFunction.Function,
		TypeTags:        entryFunction.ArgTypes,
		BcsValues:       entryFunction.Args,
		Status:          commontypes.Pending,
		Simulate:        simulateTx,
	}

	err = a.enqueueTransaction(tx)
	if err != nil {
		return "", fmt.Errorf("failed to enqueue transaction: %+w", err)
	}

	return tx.ID, nil
}

// enqueueTransaction is the common helper that handles pruning, storing, and broadcasting
// a transaction. Both Enqueue and EnqueueWithEntryFunction use this after building the AptosTx.
func (a *AptosTxm) enqueueTransaction(tx *AptosTx) error {
	ctxLogger := GetContexedTxLogger(a.baseLogger, tx.ID, tx.Metadata)

	a.transactionsLock.Lock()
	currentTimestamp := tx.Timestamp
	if (currentTimestamp - a.transactionsLastPruneTime) > *a.config.PruneIntervalSecs {
		for txID, existingTx := range a.transactions {
			if existingTx.Status != commontypes.Finalized && existingTx.Status != commontypes.Failed && existingTx.Status != commontypes.Fatal {
				continue
			}
			if (currentTimestamp - existingTx.Timestamp) < *a.config.PruneTxExpirationSecs {
				continue
			}
			ctxLogger.Debugw("Pruning transaction", "status", existingTx.Status)
			delete(a.transactions, txID)
		}
		a.transactionsLastPruneTime = currentTimestamp
	}
	a.transactions[tx.ID] = tx
	a.transactionsLock.Unlock()

	select {
	case a.broadcastChan <- tx.ID:
		ctxLogger.Debugw("tx enqueued", "fromAddr", tx.FromAddress.String(), "transactionID", tx.ID)
	default:
		// if the channel is full, we drop the transaction.
		// we do this instead of setting the tx in `a.transactions` post-broadcast to avoid a race
		// with the broadcastLoop, which expects to find the tx in `a.transactions` upon reception of
		// the id.
		a.transactionsLock.Lock()
		delete(a.transactions, tx.ID)
		a.transactionsLock.Unlock()

		ctxLogger.Errorw("broadcast channel full, tx dropped", "transactionID", tx.ID)
		return fmt.Errorf("failed to enqueue tx: %+v", tx)
	}

	return nil
}

func (a *AptosTxm) GetStatus(transactionID string) (commontypes.TransactionStatus, error) {
	if transactionID == "" {
		return commontypes.Unknown, errors.New("nil tx id")
	}

	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx, ok := a.transactions[transactionID]
	if !ok {
		return commontypes.Unknown, errors.New("no such tx")
	}

	return tx.Status, nil
}

func (a *AptosTxm) GetTransactionFee(ctx context.Context, transactionID string) (*big.Int, error) {
	if transactionID == "" {
		return nil, errors.New("nil tx id")
	}

	a.transactionsLock.RLock()
	defer a.transactionsLock.RUnlock()
	tx, ok := a.transactions[transactionID]
	if !ok {
		return nil, errors.New("no such tx")
	}

	if tx.Status != commontypes.Finalized {
		return nil, fmt.Errorf("transaction not finalized, current status: %v", tx.Status)
	}

	if tx.Fee == nil {
		return nil, errors.New("transaction fee not available")
	}

	return tx.Fee, nil
}

type TransactionResult struct {
	Status   commontypes.TransactionStatus
	TxHash   string
	VmStatus string
}

func (a *AptosTxm) GetTransactionResult(transactionID string) (*TransactionResult, error) {
	if transactionID == "" {
		return nil, errors.New("nil tx id")
	}

	a.transactionsLock.RLock()
	defer a.transactionsLock.RUnlock()
	tx, ok := a.transactions[transactionID]
	if !ok {
		return nil, errors.New("no such tx")
	}

	return &TransactionResult{
		Status:   tx.Status,
		TxHash:   tx.TxHash,
		VmStatus: tx.VmStatus,
	}, nil
}

func (a *AptosTxm) broadcastLoop() {
	defer a.done.Done()

	ctx, cancel := commonutils.ContextFromChan(a.stop)
	defer cancel()

	a.baseLogger.Debugw("broadcastLoop: started")
	for {
		select {
		case initialId := <-a.broadcastChan:
			broadcastIds := []string{initialId}
			// read all available ids on broadcastChan without blocking, and broadcast in order of which they were
			// queued. this means that retries would take priority over newly submitted transactions.
		DrainChannel:
			for {
				select {
				case nextId := <-a.broadcastChan:
					broadcastIds = append(broadcastIds, nextId)
				default:
					break DrainChannel
				}
			}

			a.transactionsLock.RLock()
			broadcastTxs := []*AptosTx{}
			for _, transactionId := range broadcastIds {
				tx, ok := a.transactions[transactionId]
				if !ok {
					a.baseLogger.Errorw("failed to find tx", "txID", transactionId)
					continue
				}
				broadcastTxs = append(broadcastTxs, tx)
			}
			a.transactionsLock.RUnlock()

			sort.Slice(broadcastTxs, func(i, j int) bool {
				return broadcastTxs[i].Timestamp < broadcastTxs[j].Timestamp
			})

			for _, tx := range broadcastTxs {
				a.signAndBroadcast(ctx, tx)
			}
		case <-a.stop:
			a.baseLogger.Debugw("broadcastLoop: stopped")
			return
		}
	}
}

func (a *AptosTxm) createRawTx(client aptos.AptosRpcClient, tx *AptosTx, nonce uint64) (*aptos.RawTransaction, error) {
	// this is cached within NodeClient after the first successful invocation.
	chainId, err := client.GetChainId()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain id: %w", err)
	}

	ledgerTimestampSecs, err := a.getLedgerTimestampSecs(client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ledger timestamp: %w", err)
	}

	expirationTimestampSecs := ledgerTimestampSecs + *a.config.TxExpirationSecs

	payload := aptos.TransactionPayload{
		Payload: &aptos.EntryFunction{
			Module: aptos.ModuleId{
				Address: tx.ContractAddress,
				Name:    tx.ModuleName,
			},
			Function: tx.FunctionName,
			ArgTypes: tx.TypeTags,
			Args:     tx.BcsValues,
		},
	}

	rawTx := &aptos.RawTransaction{
		Sender:                     tx.FromAddress,
		SequenceNumber:             nonce,
		Payload:                    payload,
		MaxGasAmount:               0, // populated below
		GasUnitPrice:               0, // populated below
		ExpirationTimestampSeconds: expirationTimestampSecs,
		ChainId:                    chainId,
	}

	ctxLogger := GetContexedTxLogger(a.baseLogger, tx.ID, tx.Metadata)

	if tx.Metadata != nil && tx.Metadata.GasLimit != nil {
		rawTx.MaxGasAmount = tx.Metadata.GasLimit.Uint64()
		ctxLogger.Debugw("using gas limit from metadata", "maxGasAmount", rawTx.MaxGasAmount)
	}

	// (if enabled for tx) simulate tx to estimate gas
	if tx.Simulate {
		simulatedTx, err := a.simulateTransaction(client, *rawTx, tx.FromAddress, tx.PublicKey)
		if err == nil {
			ctxLogger.Debugw("simulate tx successful", "gasUsed", simulatedTx.GasUsed, "gasUnitPrice", simulatedTx.GasUnitPrice)

			if tx.Metadata != nil && tx.Metadata.GasLimit != nil {
				if simulatedTx.GasUsed > rawTx.MaxGasAmount {
					ctxLogger.Warnw("simulated gas used exceeds gas limit from metadata", "gasUsed", simulatedTx.GasUsed, "maxGasAmount", rawTx.MaxGasAmount)
				}
			} else {
				rawTx.MaxGasAmount = simulatedTx.GasUsed
			}

			rawTx.GasUnitPrice = simulatedTx.GasUnitPrice
		} else {
			if matchExpectedSimulationFailure(err, tx.ExpectedSimulationFailureRules) {
				return nil, &expectedSimulationFailureError{reason: err.Error()}
			}
			// do not error on failed estimate gas as it could fail due to conflicting in-flight txs
			ctxLogger.Errorw("failed to simulate tx", "error", err)
		}
	}

	if rawTx.GasUnitPrice == 0 {
		// If simulate was disabled or failed, populate the gas unit price.
		gasInfo, err := client.EstimateGasPrice()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve estimated gas price: %w", err)
		}

		ctxLogger.Debugw("estimated gas price", "gasEstimate", gasInfo.GasEstimate, "prioritizedGasEstimate", gasInfo.PrioritizedGasEstimate)

		// use prioritized fee for sebsequent attempts
		if tx.Attempt > 0 {
			rawTx.GasUnitPrice = gasInfo.PrioritizedGasEstimate
		} else {
			rawTx.GasUnitPrice = gasInfo.GasEstimate
		}
	}

	if rawTx.MaxGasAmount == 0 {
		rawTx.MaxGasAmount = *a.config.DefaultMaxGasAmount
		ctxLogger.Debugw("using default max gas amount", "maxGasAmount", *a.config.DefaultMaxGasAmount)
	}

	if *a.config.GasLimitOverhead > 0 {
		originalGasLimit := rawTx.MaxGasAmount
		rawTx.MaxGasAmount += *a.config.GasLimitOverhead
		ctxLogger.Debugw("added gas limit overhead",
			"original", originalGasLimit,
			"overhead", *a.config.GasLimitOverhead,
			"final", rawTx.MaxGasAmount)
	}

	return rawTx, nil
}

func (a *AptosTxm) createSignedTx(client aptos.AptosRpcClient, rawTx *aptos.RawTransaction, publicKey ed25519.PublicKey, fromAddress aptos.AccountAddress) (*aptos.SignedTransaction, error) {
	signingMessage, err := rawTx.SigningMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to create signing message: %w", err)
	}

	signature, err := a.keystore.Sign(context.Background(), fmt.Sprintf("%064x", publicKey), signingMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message for address %s: %w", fromAddress, err)
	}

	sig := aptoscrypto.Ed25519Signature{}
	err = sig.FromBytes(signature)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize signature: %w", err)
	}

	authenticator := &aptoscrypto.Ed25519Authenticator{
		PubKey: &aptoscrypto.Ed25519PublicKey{Inner: publicKey},
		Sig:    &sig,
	}

	signedTx, err := rawTx.SignedTransactionWithAuthenticator(&aptoscrypto.AccountAuthenticator{
		Variant: aptoscrypto.AccountAuthenticatorEd25519,
		Auth:    authenticator,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign tx: %w", err)
	}

	return signedTx, nil
}

func (a *AptosTxm) updateTransactionStatus(tx *AptosTx, status commontypes.TransactionStatus) {
	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()

	tx.Status = status
}

func (a *AptosTxm) updateTransactionFee(tx *AptosTx, fee *big.Int) {
	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx.Fee = fee
}

func (a *AptosTxm) updateTransactionHash(tx *AptosTx, hash string) {
	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx.TxHash = hash
}

func (a *AptosTxm) updateTransactionVmStatus(tx *AptosTx, vmStatus string) {
	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx.VmStatus = vmStatus
}

func (a *AptosTxm) incrementTransactionAttempt(tx *AptosTx) {
	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx.Attempt++
}

func (a *AptosTxm) getTransactionAttempt(tx *AptosTx) uint64 {
	a.transactionsLock.RLock()
	defer a.transactionsLock.RUnlock()
	return tx.Attempt
}

func (a *AptosTxm) signAndBroadcast(ctx context.Context, tx *AptosTx) {
	ctxLogger := GetContexedTxLogger(a.baseLogger, tx.ID, tx.Metadata)
	client, err := a.getClient()
	if err != nil {
		ctxLogger.Errorw("Unable to sign and broadcast: failed to get client", "error", err)
		return
	}

	txStore := a.accountStore.GetTxStore(tx.FromAddress.String())
	if txStore == nil {
		sequenceNumber, err := a.getSequenceNumber(client, tx.FromAddress)
		if err != nil {
			ctxLogger.Errorw("failed to get sequence number", "fromAddress", tx.FromAddress.String(), "error", err)
			a.updateTransactionStatus(tx, commontypes.Failed)
			a.metrics.IncrementErrorTxs(ctx)
			return
		}
		newTxStore, err := a.accountStore.CreateTxStore(tx.FromAddress.String(), sequenceNumber)
		if err != nil {
			ctxLogger.Errorw("failed to create tx store", "fromAddress", tx.FromAddress.String(), "error", err)
			a.updateTransactionStatus(tx, commontypes.Failed)
			a.metrics.IncrementErrorTxs(ctx)
			return
		}
		txStore = newTxStore
	}

	currentAttempt := a.getTransactionAttempt(tx)
	if currentAttempt > 0 {
		// If we're retrying a failed transaction that we caught in the confirm loop, resync the nonce again
		// first.
		_ = a.resyncNonce(client, tx)
	}

	// broadcast with basic retry to try get the tx included in the mempool
	for attempt := 1; attempt <= int(*a.config.MaxSubmitRetryAttempts); attempt++ {
		// build the tx with the nonce and expiration timestamp
		nonce := txStore.GetNextNonce()

		rawTx, err := a.createRawTx(client, tx, nonce)
		if err != nil {
			a.updateTransactionStatus(tx, commontypes.Failed)
			if !errors.As(err, new(*expectedSimulationFailureError)) {
				ctxLogger.Errorw("failed to create raw tx", "error", err)
				a.metrics.IncrementErrorTxs(ctx)
			}
			return
		}

		signedTx, err := a.createSignedTx(client, rawTx, tx.PublicKey, tx.FromAddress)
		if err != nil {
			ctxLogger.Errorw("failed to create signed tx", "error", err)
			a.updateTransactionStatus(tx, commontypes.Failed)
			a.metrics.IncrementErrorTxs(ctx)
			return
		}

		submitResponse, err := client.SubmitTransaction(signedTx)
		if err == nil {
			if submitResponse == nil || submitResponse.Hash == "" {
				ctxLogger.Errorw("did not receive hash after successful tx submission")
				a.updateTransactionStatus(tx, commontypes.Failed)
				a.metrics.IncrementErrorTxs(ctx)
				return
			}

			// tx included in the Mempool
			currentAttempt := a.getTransactionAttempt(tx)
			ctxLogger.Debugw("submit tx successful", "attempt", currentAttempt, "submitResponse", submitResponse)

			a.updateTransactionHash(tx, submitResponse.Hash)

			err = txStore.AddUnconfirmed(nonce, submitResponse.Hash, rawTx.ExpirationTimestampSeconds, tx)
			if err != nil {
				// TODO: figure out what to do here, this should never occur.
				ctxLogger.Errorw("failed to add unconfirmed tx", "txHash", submitResponse.Hash, "error", err)
				a.updateTransactionStatus(tx, commontypes.Failed)
				a.metrics.IncrementErrorTxs(ctx)
				return
			}

			a.updateTransactionStatus(tx, commontypes.Unconfirmed)
			a.metrics.IncrementBroadcastedTxs(ctx)
			return
		} else {
			// In case of http errors (>400) wait gracefully and retry
			// It includes all network-related errors as well as
			// the pre-execution validation in the Mempool (e.g. old/duplicated nonce, transaction expired)
			var httpError *aptos.HttpError
			if !errors.As(err, &httpError) {
				// Do not retry on unknown errors
				ctxLogger.Errorw("failed to submit signed tx, discarding..", "error", err)
				a.updateTransactionStatus(tx, commontypes.Failed)
				a.metrics.IncrementErrorTxs(ctx)
				return
			}

			ctxLogger.Errorw("failed to submit signed tx, retrying..", "error", httpError)
			time.Sleep(time.Duration(*a.config.SubmitDelayDuration) * time.Second)

			httpErrorBody := string(httpError.Body)
			if strings.Contains(httpErrorBody, "SEQUENCE_NUMBER_TOO_OLD") || strings.Contains(httpErrorBody, "SEQUENCE_NUMBER_TOO_NEW") {
				// Try to resync the nonce before the next attempt.
				_ = a.resyncNonce(client, tx)
			}
		}
	}

	ctxLogger.Errorw("reached max retries for submitting the tx")
	a.updateTransactionStatus(tx, commontypes.Failed)
	a.metrics.IncrementRejectTxs(ctx)
	a.metrics.IncrementErrorTxs(ctx)
}

func matchExpectedSimulationFailure(err error, expectedSimulationFailures []ExpectedSimulationFailureRule) bool {
	if err == nil {
		return false
	}

	errMsg := err.Error()
	for _, expectedSimulationFailure := range expectedSimulationFailures {
		if strings.Contains(errMsg, expectedSimulationFailure.ErrorContains) {
			return true
		}
	}

	return false
}

func (a *AptosTxm) confirmLoop() {
	defer a.done.Done()

	ctx, cancel := commonutils.ContextFromChan(a.stop)
	defer cancel()

	pollDuration := time.Duration(*a.config.ConfirmPollSecs) * time.Second
	tick := time.After(pollDuration)

	a.baseLogger.Debugw("confirmLoop: started")

	for {
		select {
		case <-tick:
			start := time.Now()

			a.checkUnconfirmed(ctx)

			remaining := pollDuration - time.Since(start)
			if remaining > 0 {
				// reset tick for the remaining time
				tick = time.After(commonutils.WithJitter(remaining))
			} else {
				// reset tick to fire immediately
				tick = time.After(0)
			}
		case <-a.stop:
			a.baseLogger.Debugw("confirmLoop: stopped")
			return
		}
	}
}

// checkUnconfirmed polls committed/pending txs and moves them to terminal states
// Possible terminal states from this method:
//   - Finalized: tx committed on-chain (successful OR reverted with non-OOG VmStatus — see TODO below)
//   - Failed: OOG revert after max retries, expired tx after max retries, or TxStore errors
func (a *AptosTxm) checkUnconfirmed(ctx context.Context) {
	client, err := a.getClient()
	if err != nil {
		a.baseLogger.Errorw("Unable to check unconfirmed: failed to get client", "error", err)
		return
	}
	allUnconfirmedTxs := a.accountStore.GetAllUnconfirmed()

	totalPending := 0
	for accountAddress, unconfirmedTxs := range allUnconfirmedTxs {
		txStore := a.accountStore.GetTxStore(accountAddress)

		for _, unconfirmedTx := range unconfirmedTxs {
			ctxLogger := GetContexedTxLogger(a.baseLogger, unconfirmedTx.Tx.ID, unconfirmedTx.Tx.Metadata)
			hash := unconfirmedTx.Hash
			// NOTE: TransactionByHash errors (network failure, RPC error, not just "not found")
			// are all treated as "tx still unconfirmed" and fall through to the expiry check below.
			chainTx, err := client.TransactionByHash(hash)

			if err == nil && chainTx.Type != aptosapi.TransactionVariantPending { // tx has been committed

				// confirm nonce
				if err := txStore.Confirm(unconfirmedTx.Nonce, hash, false); err != nil {
					ctxLogger.Errorw("failed to confirm tx in TxStore", "hash", hash, "accountAddress", accountAddress, "error", err)
				}

				if chainTx.Type == aptosapi.TransactionVariantUser {
					userTx, ok := chainTx.Inner.(*aptosapi.UserTransaction)
					if ok {
						a.updateTransactionVmStatus(unconfirmedTx.Tx, userTx.VmStatus)

						if userTx.Success {
							ctxLogger.Infow("confirmed tx: successful", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
							a.metrics.IncrementSuccessTxs(ctx)

							// Calculate and store the transaction fee
							gasUsed := userTx.GasUsed
							gasUnitPrice := userTx.GasUnitPrice
							if gasUsed > 0 && gasUnitPrice > 0 {
								fee := new(big.Int).SetUint64(gasUsed * gasUnitPrice)
								a.updateTransactionFee(unconfirmedTx.Tx, fee)
								ctxLogger.Debugw("stored transaction fee", "fee", fee.String(), "gasUsed", gasUsed, "gasUnitPrice", gasUnitPrice)
							}
						} else {
							ctxLogger.Infow("confirmed tx: unsuccessful", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
							a.metrics.IncrementRevertTxs(ctx)
							a.metrics.IncrementErrorTxs(ctx)
							if userTx.VmStatus == "Out of gas" {
								// https://github.com/aptos-labs/aptos-core/blob/77ff4bf413f54c41206bd5573e1891fa3a0dccf6/api/types/src/convert.rs#L1062
								// Example transaction: https://api.testnet.aptoslabs.com/v1/transactions/by_hash/0x7a106db811c8d5dfd71ac98f374ca36e4f630ce5412b99c8f0e871e7feda37ea
								a.incrementTransactionAttempt(unconfirmedTx.Tx)
								if !a.maybeRetry(ctx, unconfirmedTx, RetryReasonOutOfGas) {
									a.updateTransactionStatus(unconfirmedTx.Tx, commontypes.Failed)
								}
								continue
							}
						}
					} else {
						// NOTE: Type assertion failed on UserTransaction.
						ctxLogger.Errorw("failed to read confirmed user tx", "hash", hash, "chainTxInner", chainTx.Inner)
						// Incrementing error as we dont know if it was a success.
						a.metrics.IncrementErrorTxs(ctx)
					}
				} else {
					// NOTE: Committed tx is not TransactionVariantUser (e.g. some future variant).
					ctxLogger.Errorw("unexpected confirmed tx type", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
					// Incrementing error as we dont know if it was a success.
					a.metrics.IncrementErrorTxs(ctx)
				}

				a.updateTransactionStatus(unconfirmedTx.Tx, commontypes.Finalized)
				a.metrics.IncrementFinalizedTxs(ctx)
			} else {
				ctxLogger.Debugw("tx is still unconfirmed", "hash", hash, "chainTx", chainTx)
				// Check using the ledger timestamp whether the transaction has expired.
				ledgerTimestampSecs, err := a.getLedgerTimestampSecs(client)
				if err != nil {
					ctxLogger.Errorw("couldn't fetch ledger timestamp and check if tx expired", "error", err)
					continue
				}

				if ledgerTimestampSecs <= unconfirmedTx.ExpirationTimestampSecs {
					// tx was neither committed nor expired yet
					totalPending++
					ctxLogger.Debugw("tx not found or pending in the mempool", "hash", hash)
					continue
				}

				// Confirm the transaction, mark as failed to reuse the nonce.
				err = txStore.Confirm(unconfirmedTx.Nonce, hash, true)
				if err != nil {
					ctxLogger.Errorw("couldn't confirm expired tx", "error", err)
					a.updateTransactionStatus(unconfirmedTx.Tx, commontypes.Failed)
					a.metrics.IncrementErrorTxs(ctx)
					continue
				}

				a.metrics.IncrementDropTxs(ctx)
				a.metrics.IncrementErrorTxs(ctx)
				a.incrementTransactionAttempt(unconfirmedTx.Tx)
				if !a.maybeRetry(ctx, unconfirmedTx, RetryReasonExpired) {
					a.updateTransactionStatus(unconfirmedTx.Tx, commontypes.Failed)
				}
			}
		}
	}
	a.metrics.SetPendingTxs(ctx, totalPending)
}

type RetryReason int

const (
	RetryReasonOutOfGas RetryReason = iota
	RetryReasonExpired
)

func (r RetryReason) String() string {
	switch r {
	case RetryReasonOutOfGas:
		return "out of gas"
	case RetryReasonExpired:
		return "expired"
	default:
		return "unknown"
	}
}

func (a *AptosTxm) maybeRetry(ctx context.Context, unconfirmedTx *UnconfirmedTx, retryReason RetryReason) bool {
	ctxLogger := GetContexedTxLogger(a.baseLogger, unconfirmedTx.Tx.ID, unconfirmedTx.Tx.Metadata)
	currentAttempt := a.getTransactionAttempt(unconfirmedTx.Tx)
	if currentAttempt >= *a.config.MaxTxRetryAttempts {
		ctxLogger.Errorw("tx reached max num of retries and will be discarded", "hash", unconfirmedTx.Hash, "retryReason", retryReason)
		return false
	}

	select {
	case a.broadcastChan <- unconfirmedTx.Tx.ID:
		ctxLogger.Debugw("retrying tx", "attempt", currentAttempt, "hash", unconfirmedTx.Hash, "retryReason", retryReason)
		a.metrics.IncrementRetryTxs(ctx)
		return true
	default:
		ctxLogger.Errorw("failed to enqueue tx for rebroadcast", "attempt", currentAttempt, "hash", unconfirmedTx.Hash, "retryReason", retryReason)
		return false
	}
}

func (a *AptosTxm) InflightCount() (int, int) {
	return len(a.broadcastChan), a.accountStore.GetTotalInflightCount()
}

func (a *AptosTxm) getSequenceNumber(client aptos.AptosRpcClient, address aptos.AccountAddress) (uint64, error) {
	accountInfo, err := client.Account(address)
	if err != nil {
		return 0, fmt.Errorf("failed to fetch account data for address %s: %w", address, err)
	}
	sequenceNumber, err := accountInfo.SequenceNumber()
	if err != nil {
		return 0, fmt.Errorf("failed to decode sequence number from %s: %w", accountInfo.SequenceNumberStr, err)
	}
	return sequenceNumber, nil
}

func (a *AptosTxm) resyncNonce(client aptos.AptosRpcClient, tx *AptosTx) error {
	address := tx.FromAddress
	sequenceNumber, err := a.getSequenceNumber(client, address)
	if err != nil {
		return fmt.Errorf("failed to resync nonce for address %s: %w", address.String(), err)
	}

	txStore := a.accountStore.GetTxStore(address.String())
	// this should never occur, as resyncNonce is only called after ensuring a TxStore exists in
	// signAndBroadcast.
	if txStore == nil {
		return fmt.Errorf("failed to get tx store for address %s", address.String())
	}
	ctxLogger := GetContexedTxLogger(a.baseLogger, tx.ID, tx.Metadata)

	previousNextNonce := txStore.GetNextNonce()
	previousLastOnchainNonce := txStore.GetLastResyncedNonce()
	txStore.ResyncNonce(sequenceNumber)
	updatedNextNonce := txStore.GetNextNonce()
	updatedLastOnchainNonce := txStore.GetLastResyncedNonce()

	ctxLogger.Infow("resynced nonce", "address", address.String(), "sequenceNumber", sequenceNumber, "previousLastOnchainNonce", previousLastOnchainNonce, "updatedLastOnchainNonce", updatedLastOnchainNonce, "previousNextNonce", previousNextNonce, "updatedNextNonce", updatedNextNonce)
	return nil
}

func (a *AptosTxm) getLedgerTimestampSecs(client aptos.AptosRpcClient) (uint64, error) {
	nodeInfo, err := client.Info()
	if err != nil {
		return 0, fmt.Errorf("failed to fetch node info: %+w", err)
	}

	ledgerTimestamp := nodeInfo.LedgerTimestamp()
	if ledgerTimestamp == 0 {
		return 0, fmt.Errorf("ledgerTimestamp is 0")
	}

	// ledger timestamp is in microseconds, convert to seconds.
	return ledgerTimestamp / 1000000, nil
}

type mockSimulationSigner struct {
	aptoscrypto.Ed25519PrivateKey
	pubKey aptoscrypto.Ed25519PublicKey
}

var _ aptoscrypto.Signer = &mockSimulationSigner{}

func (key *mockSimulationSigner) PubKey() aptoscrypto.PublicKey {
	return &key.pubKey
}

func (key *mockSimulationSigner) SimulationAuthenticator() *aptoscrypto.AccountAuthenticator {
	return &aptoscrypto.AccountAuthenticator{
		Variant: aptoscrypto.AccountAuthenticatorEd25519,
		Auth: &aptoscrypto.Ed25519Authenticator{
			PubKey: &key.pubKey,
			Sig:    &aptoscrypto.Ed25519Signature{},
		},
	}
}

func (a *AptosTxm) simulateTransaction(client aptos.AptosRpcClient, rawTx aptos.RawTransaction, fromAddress aptos.AccountAddress, publicKey ed25519.PublicKey) (*aptosapi.UserTransaction, error) {
	// build mock signer for simulation
	signerForSimulation := &aptos.Account{Signer: &mockSimulationSigner{pubKey: aptoscrypto.Ed25519PublicKey{Inner: publicKey}}}

	attempt := 1
	var lastError error
	for attempt <= int(*a.config.MaxSimulateAttempts) {
		// need to fetch latest sequence number on-chain since we could have other in-flight txs which results in an error SEQUENCE_NUMBER_TOO_NEW
		sequenceNumber, err := a.getSequenceNumber(client, fromAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to get sequence number: %w", err)
		}
		rawTx.SequenceNumber = sequenceNumber

		// TODO: consider using EstimatePrioritizedGasUnitPrice(true)
		txs, err := client.SimulateTransaction(&rawTx, signerForSimulation, aptos.EstimateMaxGasAmount(true), aptos.EstimateGasUnitPrice(true))
		if err != nil {
			return nil, err
		}

		if len(txs) < 1 {
			return nil, errors.New("no simulated tx returned")
		}
		simulateResponse := txs[0]
		if simulateResponse == nil {
			return nil, errors.New("empty simulated response")
		}

		if !simulateResponse.Success {
			if simulateResponse.VmStatus == "SEQUENCE_NUMBER_TOO_OLD" || simulateResponse.VmStatus == "SEQUENCE_NUMBER_TOO_NEW" {
				// race condition with tx confirmation incrementing the sequence number, retry
				lastError = fmt.Errorf("simulate bad status: %v", simulateResponse.VmStatus)
				attempt = attempt + 1
				continue
			}

			return nil, fmt.Errorf("simulated tx unexpected status: %v", simulateResponse.VmStatus)
		}

		return simulateResponse, nil
	}

	return nil, fmt.Errorf("simulation attempts failed, last error: %w", lastError)
}

func getTimestampSecs() uint64 {
	return uint64(time.Now().Unix())
}
