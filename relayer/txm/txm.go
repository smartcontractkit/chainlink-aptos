package txm

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
	"github.com/smartcontractkit/chainlink-common/pkg/utils"

	aptosacc "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/account"
)

var _ services.Service = &AptosTxm{}

type AptosTxm struct {
	baseLogger logger.Logger
	keystore   loop.Keystore
	config     Config

	transactions              map[string]*AptosTx
	transactionsLock          sync.RWMutex
	transactionsLastPruneTime uint64

	broadcastChan chan string
	accountStore  *AccountStore
	starter       utils.StartStopOnce
	done          sync.WaitGroup
	stop          chan struct{}

	client *aptos.NodeClient
}

// TODO: Config input is not validated for sanity
func New(lgr logger.Logger, keystore loop.Keystore, config Config, getClient func() (*aptos.NodeClient, error)) (*AptosTxm, error) {
	client, err := getClient()
	if err != nil {
		return nil, err
	}

	return &AptosTxm{
		baseLogger: logger.Named(lgr, "AptosTxm"),
		keystore:   keystore,
		config:     config,
		client:     client,

		transactions:              map[string]*AptosTx{},
		transactionsLastPruneTime: getTimestampSecs(),

		broadcastChan: make(chan string, config.BroadcastChanSize),
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
	return a.starter.StartOnce("AptosTxm", func() error {
		go a.broadcastLoop()
		go a.confirmLoop()
		return nil
	})
}

func (a *AptosTxm) Close() error {
	return a.starter.StopOnce("AptosTxm", func() error {
		close(a.stop)
		a.done.Wait()
		return nil
	})
}

func (a *AptosTxm) Enqueue(transactionID string, fromAddress, publicKey, function string, typeArgs []string, paramTypes []string, paramValues []any, simulateTx bool) error {
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

	ctxLogger := logger.With(a.baseLogger, "txID", transactionID)

	ed25519PublicKey, err := aptosacc.HexToEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %+w", err)
	}

	if fromAddress == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		acc := aptosacc.Ed25519PublicKeyToAccount(ed25519PublicKey)
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
			return fmt.Errorf("failed to parse type %s: %+w", typeName, err)
		}

		bcsValue, err := CreateBcsValue(typeTag, typeValue)
		if err != nil {
			return fmt.Errorf("failed to serialize value %s: %+w", typeValue, err)
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

	currentTimestamp := getTimestampSecs()
	tx := &AptosTx{
		ID:              transactionID,
		Timestamp:       currentTimestamp,
		FromAddress:     *fromAccountAddress,
		PublicKey:       ed25519PublicKey,
		ContractAddress: *contractAccountAddress,
		ModuleName:      moduleName,
		FunctionName:    functionName,
		TypeTags:        typeTags,
		BcsValues:       bcsValues,
		Status:          commontypes.Pending,
		Simulate:        simulateTx,
	}

	a.transactionsLock.Lock()
	if (currentTimestamp - a.transactionsLastPruneTime) > a.config.PruneIntervalSecs {
		for txID, tx := range a.transactions {
			if tx.Status != commontypes.Finalized && tx.Status != commontypes.Failed && tx.Status != commontypes.Fatal {
				continue
			}
			if (currentTimestamp - tx.Timestamp) < a.config.PruneTxExpirationSecs {
				continue
			}
			a.baseLogger.Debugw("Pruning transaction", "txID", txID, "status", tx.Status)
			delete(a.transactions, txID)
		}
		a.transactionsLastPruneTime = currentTimestamp
	}
	a.transactions[transactionID] = tx
	a.transactionsLock.Unlock()

	select {
	case a.broadcastChan <- transactionID:
		ctxLogger.Debugw("Tx enqueued", "fromAddr", fromAddress)
	default:
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

func (a *AptosTxm) broadcastLoop() {
	defer a.done.Done()

	_, cancel := utils.ContextFromChan(a.stop)
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

			a.transactionsLock.Lock()
			broadcastTxs := []*AptosTx{}
			for _, transactionId := range broadcastIds {
				tx, ok := a.transactions[transactionId]
				if !ok {
					a.baseLogger.Errorw("failed to find tx", "txID", transactionId)
					continue
				}
				broadcastTxs = append(broadcastTxs, tx)
			}
			a.transactionsLock.Unlock()

			sort.Slice(broadcastTxs, func(i, j int) bool {
				return broadcastTxs[i].Timestamp < broadcastTxs[j].Timestamp
			})

			for _, tx := range broadcastTxs {
				a.signAndBroadcast(tx)
			}
		case <-a.stop:
			a.baseLogger.Debugw("broadcastLoop: stopped")
			return
		}
	}
}

func (a *AptosTxm) createRawTx(client *aptos.NodeClient, tx *AptosTx, nonce uint64) (*aptos.RawTransaction, error) {
	// this is cached within NodeClient after the first successful invocation.
	chainId, err := client.GetChainId()
	if err != nil {
		return nil, fmt.Errorf("failed to get chain id: %w", err)
	}

	ledgerTimestampSecs, err := a.getLedgerTimestampSecs(client)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch ledger timestamp: %w", err)
	}

	expirationTimestampSecs := ledgerTimestampSecs + a.config.TxExpirationSecs

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

	ctxLogger := logger.With(a.baseLogger, "txID", tx.ID)

	// (if enabled for tx) simulate tx to estimate gas
	if tx.Simulate {
		simulatedTx, err := a.simulateTransaction(client, *rawTx, tx.FromAddress, tx.PublicKey)
		if err == nil {
			ctxLogger.Debugw("simulate tx successful", "gasUsed", simulatedTx.GasUsed, "gasUnitPrice", simulatedTx.GasUnitPrice)

			// todo: configurable multiplier?
			// fixed multiplier of 1.25 to account for potential discrepancies in gas estimation
			rawTx.MaxGasAmount = uint64(float64(simulatedTx.GasUsed) * 1.25)
			rawTx.GasUnitPrice = simulatedTx.GasUnitPrice
		} else {
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
		rawTx.MaxGasAmount = a.config.DefaultMaxGasAmount
		ctxLogger.Debugw("using default max gas amount", "maxGasAmount", a.config.DefaultMaxGasAmount)
	}

	return rawTx, nil
}

func (a *AptosTxm) createSignedTx(client *aptos.NodeClient, rawTx *aptos.RawTransaction, publicKey ed25519.PublicKey, fromAddress aptos.AccountAddress) (*aptos.SignedTransaction, error) {
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

func (a *AptosTxm) signAndBroadcast(tx *AptosTx) {
	client := a.client
	ctxLogger := logger.With(a.baseLogger, "txID", tx.ID)

	txStore := a.accountStore.GetTxStore(tx.FromAddress.String())
	if txStore == nil {
		sequenceNumber, err := a.getSequenceNumber(client, tx.FromAddress)
		if err != nil {
			ctxLogger.Errorw("failed to get sequence number", "fromAddress", tx.FromAddress, "error", err)
			tx.Status = commontypes.Failed
			return
		}
		newTxStore, err := a.accountStore.CreateTxStore(tx.FromAddress.String(), sequenceNumber)
		if err != nil {
			ctxLogger.Errorw("failed to create tx store", "fromAddress", tx.FromAddress, "error", err)
			tx.Status = commontypes.Failed
			return
		}
		txStore = newTxStore
	}

	if tx.Attempt > 0 {
		// If we're retrying a failed transaction that we caught in the confirm loop, resync the nonce again
		// first.
		a.resyncNonce(client, tx.FromAddress)
	}

	// broadcast with basic retry to try get the tx included in the mempool
	for attempt := 1; attempt <= int(a.config.MaxSubmitRetryAttempts); attempt++ {
		// build the tx with the nonce and expiration timestamp
		nonce := txStore.GetNextNonce()

		rawTx, err := a.createRawTx(client, tx, nonce)
		if err != nil {
			ctxLogger.Errorw("failed to create raw tx", "error", err)
			tx.Status = commontypes.Failed
			return
		}

		signedTx, err := a.createSignedTx(client, rawTx, tx.PublicKey, tx.FromAddress)
		if err != nil {
			ctxLogger.Errorw("failed to create signed tx", "error", err)
			tx.Status = commontypes.Failed
			return
		}

		submitResponse, err := client.SubmitTransaction(signedTx)
		if err == nil {
			if submitResponse.Hash == "" {
				ctxLogger.Errorw("did not receive hash after successful tx submission")
				tx.Status = commontypes.Failed
				return
			}

			// tx included in the Mempool
			ctxLogger.Debugw("submit tx successful", "attempt", tx.Attempt, "submitResponse", submitResponse)

			err = txStore.AddUnconfirmed(nonce, submitResponse.Hash, rawTx.ExpirationTimestampSeconds, tx)
			if err != nil {
				// TODO: figure out what to do here, this should never occur.
				ctxLogger.Errorw("failed to add unconfirmed tx", "txHash", submitResponse.Hash, "error", err)
				tx.Status = commontypes.Failed
				return
			}

			tx.Status = commontypes.Unconfirmed
			return
		} else {
			// In case of http errors (>400) wait gracefully and retry
			// It includes all network-related errors as well as
			// the pre-execution validation in the Mempool (e.g. old/duplicated nonce, transaction expired)
			var httpError *aptos.HttpError
			if !errors.As(err, &httpError) {
				// Do not retry on unknown errors
				ctxLogger.Errorw("failed to submit signed tx, discarding..", "error", err)
				tx.Status = commontypes.Failed
				return
			}

			ctxLogger.Errorw("failed to submit signed tx, retrying..", "error", httpError)
			time.Sleep(time.Duration(a.config.SubmitDelayDuration) * time.Second)

			httpErrorBody := string(httpError.Body)
			if strings.Contains(httpErrorBody, "SEQUENCE_NUMBER_TOO_OLD") || strings.Contains(httpErrorBody, "SEQUENCE_NUMBER_TOO_NEW") {
				// Try to resync the nonce before the next attempt.
				a.resyncNonce(client, tx.FromAddress)
			}
		}
	}

	ctxLogger.Errorw("reached max retries for submitting the tx")
	tx.Status = commontypes.Failed
}

func (a *AptosTxm) confirmLoop() {
	defer a.done.Done()

	_, cancel := utils.ContextFromChan(a.stop)
	defer cancel()

	pollDuration := time.Duration(a.config.ConfirmPollSecs) * time.Second
	tick := time.After(pollDuration)

	a.baseLogger.Debugw("confirmLoop: started")

	for {
		select {
		case <-tick:
			start := time.Now()

			a.checkUnconfirmed()

			remaining := pollDuration - time.Since(start)
			if remaining > 0 {
				// reset tick for the remaining time
				tick = time.After(utils.WithJitter(remaining))
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

func (a *AptosTxm) checkUnconfirmed() {
	client := a.client
	allUnconfirmedTxs := a.accountStore.GetAllUnconfirmed()

	for accountAddress, unconfirmedTxs := range allUnconfirmedTxs {
		txStore := a.accountStore.GetTxStore(accountAddress)

		for _, unconfirmedTx := range unconfirmedTxs {
			ctxLogger := logger.With(a.baseLogger, "txID", unconfirmedTx.Tx.ID)
			hash := unconfirmedTx.Hash
			chainTx, err := client.TransactionByHash(hash)

			if err == nil && chainTx.Type != aptosapi.TransactionVariantPending {
				// tx has been committed
				if err := txStore.Confirm(unconfirmedTx.Nonce, hash, false); err != nil {
					ctxLogger.Errorw("failed to confirm tx in TxStore", "hash", hash, "accountAddress", accountAddress, "error", err)
				}

				if chainTx.Type == aptosapi.TransactionVariantUser {
					userTx, ok := chainTx.Inner.(*aptosapi.UserTransaction)
					if ok {
						if userTx.Success {
							ctxLogger.Infow("confirmed tx: successful", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
						} else {
							ctxLogger.Infow("confirmed tx: unsuccessful", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
							if userTx.VmStatus == "Out of gas" {
								// https://github.com/aptos-labs/aptos-core/blob/77ff4bf413f54c41206bd5573e1891fa3a0dccf6/api/types/src/convert.rs#L1062
								// Example transaction: https://api.testnet.aptoslabs.com/v1/transactions/by_hash/0x7a106db811c8d5dfd71ac98f374ca36e4f630ce5412b99c8f0e871e7feda37ea
								unconfirmedTx.Tx.Attempt++
								if !a.maybeRetry(unconfirmedTx, RetryReasonOutOfGas) {
									unconfirmedTx.Tx.Status = commontypes.Failed
								}
								continue
							}
						}
					} else {
						ctxLogger.Errorw("failed to read confirmed user tx", "hash", hash, "chainTxInner", chainTx.Inner)
					}
				} else {
					ctxLogger.Errorw("unexpected confirmed tx type", "hash", hash, "chainTx", chainTx, "chainTx.Type", chainTx.Type)
				}

				unconfirmedTx.Tx.Status = commontypes.Finalized
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
					ctxLogger.Debugw("tx not found or pending in the mempool", "hash", hash)
					continue
				}

				// Confirm the transaction, mark as failed to reuse the nonce.
				err = txStore.Confirm(unconfirmedTx.Nonce, hash, true)
				if err != nil {
					ctxLogger.Errorw("coudln't confirm expired tx", "error", err)
					unconfirmedTx.Tx.Status = commontypes.Failed
					continue
				}

				unconfirmedTx.Tx.Attempt++
				if !a.maybeRetry(unconfirmedTx, RetryReasonExpired) {
					unconfirmedTx.Tx.Status = commontypes.Failed
				}
			}
		}
	}
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

func (a *AptosTxm) maybeRetry(unconfirmedTx *UnconfirmedTx, retryReason RetryReason) bool {
	ctxLogger := logger.With(a.baseLogger, "txID", unconfirmedTx.Tx.ID)
	if unconfirmedTx.Tx.Attempt >= a.config.MaxTxRetryAttempts {
		ctxLogger.Errorw("tx reached max num of retries and will be discarded", "hash", unconfirmedTx.Hash, "retryReason", retryReason)
		return false
	}

	ctxLogger.Debugw("retrying tx", "attempt", unconfirmedTx.Tx.Attempt, "hash", unconfirmedTx.Hash, "retryReason", retryReason)
	select {
	case a.broadcastChan <- unconfirmedTx.Tx.ID:
	default:
		ctxLogger.Errorw("failed to enqueue tx for rebroadcast", "attempt", unconfirmedTx.Tx.Attempt, "hash", unconfirmedTx.Hash, "retryReason", retryReason)
	}

	return true
}

func (a *AptosTxm) InflightCount() (int, int) {
	return len(a.broadcastChan), a.accountStore.GetTotalInflightCount()
}

func (a *AptosTxm) getSequenceNumber(client *aptos.NodeClient, address aptos.AccountAddress) (uint64, error) {
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

func (a *AptosTxm) resyncNonce(client *aptos.NodeClient, address aptos.AccountAddress) error {
	sequenceNumber, err := a.getSequenceNumber(client, address)
	if err != nil {
		return fmt.Errorf("failed to resync nonce for address %s: %w", address.String(), err)
	}

	txStore := a.accountStore.GetTxStore(address.String())

	previousNextNonce := txStore.GetNextNonce()
	previousLastOnchainNonce := txStore.GetLastResyncedNonce()
	txStore.ResyncNonce(sequenceNumber)
	updatedNextNonce := txStore.GetNextNonce()
	updatedLastOnchainNonce := txStore.GetLastResyncedNonce()

	a.baseLogger.Infow("resynced nonce", "address", address.String(), "sequenceNumber", sequenceNumber, "previousLastOnchainNonce", previousLastOnchainNonce, "updatedLastOnchainNonce", updatedLastOnchainNonce, "previousNextNonce", previousNextNonce, "updatedNextNonce", updatedNextNonce)
	return nil
}

func (a *AptosTxm) getLedgerTimestampSecs(client *aptos.NodeClient) (uint64, error) {
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

func (a *AptosTxm) simulateTransaction(client *aptos.NodeClient, rawTx aptos.RawTransaction, fromAddress aptos.AccountAddress, publicKey ed25519.PublicKey) (*aptosapi.UserTransaction, error) {
	// build mock signer for simulation
	signerForSimulation := &aptos.Account{Signer: &mockSimulationSigner{pubKey: aptoscrypto.Ed25519PublicKey{Inner: publicKey}}}

	attempt := 1
	var lastError error
	for attempt <= int(a.config.MaxSimulateAttempts) {
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

		if !*(simulateResponse.TxnSuccess()) {
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
