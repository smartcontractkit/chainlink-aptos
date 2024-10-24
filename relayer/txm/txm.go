package txm

import (
	"context"
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

	aptosutils "github.com/smartcontractkit/chainlink-internal-integrations/aptos/relayer/utils"
)

var _ services.Service = &AptosTxm{}

type AptosTxm struct {
	logger   logger.Logger
	keystore loop.Keystore
	config   Config

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
		logger:   logger.Named(lgr, "AptosTxm"),
		keystore: keystore,
		config:   config,
		client:   client,

		transactions:              map[string]*AptosTx{},
		transactionsLastPruneTime: getTimestampSecs(),

		broadcastChan: make(chan string, config.BroadcastChanSize),
		accountStore:  NewAccountStore(),
		stop:          make(chan struct{}),
	}, nil
}

func (a *AptosTxm) Name() string {
	return a.logger.Name()
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

	ed25519PublicKey, err := aptosutils.HexToEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %+w", err)
	}

	if fromAddress == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		acc := aptosutils.Ed25519PublicKeyToAccount(ed25519PublicKey)
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
			a.logger.Debugw("Pruning transaction", "txID", txID, "status", tx.Status)
			delete(a.transactions, txID)
		}
		a.transactionsLastPruneTime = currentTimestamp
	}
	a.transactions[transactionID] = tx
	a.transactionsLock.Unlock()

	select {
	case a.broadcastChan <- transactionID:
		a.logger.Debugw("Tx enqueued", "txID", transactionID, "fromAddr", fromAddress)
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

	a.logger.Debugw("broadcastLoop: started")
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
					a.logger.Errorw("failed to find tx", "txID", transactionId)
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
			a.logger.Debugw("broadcastLoop: stopped")
			return
		}
	}
}

func (a *AptosTxm) signAndBroadcast(tx *AptosTx) {
	client := a.client

	// this is cached within NodeClient after the first successful invocation.
	chainId, err := client.GetChainId()
	if err != nil {
		a.logger.Errorw("failed to get chain id", "error", err)
		tx.Status = commontypes.Failed
		return
	}

	txStore := a.accountStore.GetTxStore(tx.FromAddress.String())
	if txStore == nil {
		sequenceNumber, err := a.getSequenceNumber(client, tx.FromAddress)
		if err != nil {
			a.logger.Errorw("failed to get sequence number", "error", err)
			tx.Status = commontypes.Failed
			return
		}
		newTxStore, err := a.accountStore.CreateTxStore(tx.FromAddress.String(), sequenceNumber)
		if err != nil {
			a.logger.Errorw("failed to create tx store", "fromAddress", tx.FromAddress, "error", err)
			tx.Status = commontypes.Failed
			return
		}
		txStore = newTxStore
	}

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

	buildSignedTx := func(nonce uint64, expirationTimestamp uint64) (*aptos.SignedTransaction, error) {
		rawTx := aptos.RawTransaction{
			Sender:                     tx.FromAddress,
			SequenceNumber:             nonce,
			Payload:                    payload,
			MaxGasAmount:               0, // populated below
			GasUnitPrice:               0, // populated below
			ExpirationTimestampSeconds: expirationTimestamp,
			ChainId:                    chainId,
		}

		publicKey := aptoscrypto.Ed25519PublicKey{}
		err = publicKey.FromBytes([]byte(tx.PublicKey))
		if err != nil {
			a.logger.Errorw("failed to deserialize public key", "error", err)
			return nil, err
		}

		// (if enabled for tx) simulate tx to estimate gas
		if tx.Simulate {
			simulatedTx, err := a.simulateTransaction(client, rawTx, tx.FromAddress, publicKey)
			if err == nil {
				// todo: configurable multiplier?
				// fixed multiplier of 1.25 to account for potential discrepancies in gas estimation
				rawTx.MaxGasAmount = uint64(float64(simulatedTx.GasUsed) * 1.25)
				rawTx.GasUnitPrice = simulatedTx.GasUnitPrice
			} else {
				// do not error on failed estimate gas as it could fail due to conflicting in-flight txs
				a.logger.Errorw("failed to simulate tx", "error", err)
			}
		}

		if rawTx.GasUnitPrice == 0 {
			// If simulate was disabled or failed, populate the gas unit price.
			gasInfo, err := client.EstimateGasPrice()
			if err != nil {
				a.logger.Errorw("failed to retrieve estimated gas price", "error", err)
				return nil, err
			}

			a.logger.Debugw("estimated gas price", "gasEstimate", gasInfo.GasEstimate, "prioritizedGasEstimate", gasInfo.PrioritizedGasEstimate)

			// use prioritized fee for sebsequent attempts
			if tx.Attempt > 0 {
				rawTx.GasUnitPrice = gasInfo.PrioritizedGasEstimate
			} else {
				rawTx.GasUnitPrice = gasInfo.GasEstimate
			}
		}

		if rawTx.MaxGasAmount == 0 {
			rawTx.MaxGasAmount = a.config.DefaultMaxGasAmount
			a.logger.Debugw("using default max gas amount", "maxGasAmount", a.config.DefaultMaxGasAmount)
		}

		signingMessage, err := rawTx.SigningMessage()
		if err != nil {
			a.logger.Errorw("failed to create signing message", "error", err)
			return nil, err
		}

		signature, err := a.keystore.Sign(context.Background(), fmt.Sprintf("%064x", tx.PublicKey), signingMessage)
		if err != nil {
			a.logger.Errorw("failed to sign message", "fromAddress", tx.FromAddress, "error", err)
			return nil, err
		}

		sig := aptoscrypto.Ed25519Signature{}
		err = sig.FromBytes(signature)
		if err != nil {
			a.logger.Errorw("failed to deserialize signature", "error", err)
			return nil, err
		}

		authenticator := &aptoscrypto.Ed25519Authenticator{
			PubKey: &publicKey,
			Sig:    &sig,
		}

		signedTx, err := rawTx.SignedTransactionWithAuthenticator(&aptoscrypto.AccountAuthenticator{
			Variant: aptoscrypto.AccountAuthenticatorEd25519,
			Auth:    authenticator,
		})
		if err != nil {
			a.logger.Errorw("failed to sign tx", "error", err)
			return nil, err
		}

		return signedTx, nil
	}

	if tx.Attempt > 0 {
		// If we're retrying a failed transaction that we caught in the confirm loop, resync the nonce again
		// first.
		a.resyncNonce(client, tx.FromAddress)
	}

	// broadcast with basic retry to try get the tx included in the mempool
	for attempt := 1; attempt <= int(a.config.MaxSubmitRetryAttempts); attempt++ {
		ledgerTimestamp, err := a.getLedgerTimestamp()
		if err != nil {
			a.logger.Errorw("failed to fetch ledger timestamp", "error", err)
			tx.Status = commontypes.Failed
			return
		}

		expirationTimestamp := ledgerTimestamp + a.config.TxExpirationSecs

		// build the tx with the nonce and expiration timestamp
		nonce := txStore.GetNextNonce()
		signedTx, err := buildSignedTx(nonce, expirationTimestamp)
		if err != nil {
			a.logger.Errorw("failed to build signed tx", "error", err)
			tx.Status = commontypes.Failed
			return
		}

		submitResponse, err := client.SubmitTransaction(signedTx)
		if err == nil {
			if submitResponse.Hash == "" {
				a.logger.Errorw("did not receive hash after successful tx submission", "txID", tx.ID)
				tx.Status = commontypes.Failed
				return
			}

			// tx included in the Mempool
			a.logger.Debugw("submit tx successful", "txID", tx.ID, "attempt", tx.Attempt, "submitResponse", submitResponse)

			err = txStore.AddUnconfirmed(nonce, submitResponse.Hash, expirationTimestamp, tx)
			if err != nil {
				// TODO: figure out what to do here, this should never occur.
				a.logger.Errorw("failed to add unconfirmed tx", "txID", tx.ID, "txHash", submitResponse.Hash, "error", err)
				tx.Status = commontypes.Failed
				return
			}

			tx.Status = commontypes.Unconfirmed
			return
		} else {
			// In case of http errors (>400) wait gracefully and retry
			// It includes all network-related errors as well as
			// the pre-execution validation in the Mempool (e.g. old/duplicated nonce)
			var httpErr *aptos.HttpError
			if !errors.As(err, &httpErr) {
				// Do not retry on unknown errors
				a.logger.Errorw("failed to submit signed tx, discarding..", "txID", tx.ID, "error", err)
				tx.Status = commontypes.Failed
				return
			}

			a.logger.Errorw("failed to submit signed tx, retrying..", "txID", tx.ID, "error", httpErr)
			time.Sleep(time.Duration(a.config.SubmitDelayDuration) * time.Second)

			// Try to resync the nonce before the next attempt.
			a.resyncNonce(client, tx.FromAddress)
		}
	}

	a.logger.Errorw("reached max retries for submitting the tx", "txID", tx.ID)
	tx.Status = commontypes.Failed
}

func (a *AptosTxm) confirmLoop() {
	defer a.done.Done()

	_, cancel := utils.ContextFromChan(a.stop)
	defer cancel()

	tick := time.After(time.Duration(a.config.ConfirmPollSecs) * time.Second)

	a.logger.Debugw("confirmLoop: started")

	for {
		select {
		case <-tick:
			start := time.Now()

			a.checkUnconfirmed()

			remaining := time.Duration(a.config.ConfirmPollSecs) - time.Since(start)
			tick = time.After(utils.WithJitter(remaining.Abs()))
		case <-a.stop:
			a.logger.Debugw("confirmLoop: stopped")
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
			hash := unconfirmedTx.Hash
			txInfo, err := client.TransactionByHash(hash)
			a.logger.Debugw("tx info fetched", "txID", unconfirmedTx.Tx.ID, "hash", hash, "txInfo", txInfo)

			if err == nil && txInfo.Type != aptosapi.TransactionVariantPending {
				// tx has been commited
				a.logger.Debugw("tx confirmed", "txID", unconfirmedTx.Tx.ID, "hash", hash, "txInfo", txInfo)
				unconfirmedTx.Tx.Status = commontypes.Finalized

				if err := txStore.Confirm(unconfirmedTx.Nonce, hash, false); err != nil {
					a.logger.Errorw("failed to confirm tx in TxStore", "hash", hash, "accountAddress", accountAddress, "error", err)
				}
			} else {
				// Check using the ledger timestamp whether the transaction has expired.
				ledgerTimestamp, err := a.getLedgerTimestamp()
				if err != nil {
					a.logger.Errorw("couldn't fetch ledger timestamp and check if tx expired", "txID", unconfirmedTx.Tx.ID)
					continue
				}

				if ledgerTimestamp <= unconfirmedTx.ExpirationTimestamp {
					// tx was neither committed nor expired yet
					a.logger.Debugw("tx not found or pending in the mempool", "hash", hash)
					continue
				}

				// Confirm the transaction, mark as failed to reuse the nonce.
				err = txStore.Confirm(unconfirmedTx.Nonce, hash, true)
				if err != nil {
					a.logger.Errorw("coudln't confirm expired tx", "error", err)
					unconfirmedTx.Tx.Status = commontypes.Failed
					continue
				}

				unconfirmedTx.Tx.Attempt++
				if unconfirmedTx.Tx.Attempt >= a.config.MaxTxRetryAttempts {
					unconfirmedTx.Tx.Status = commontypes.Failed
					a.logger.Errorw("tx reached max num of retries and will be discarded", "txID", unconfirmedTx.Tx.ID, "hash", hash)
					continue
				}

				a.logger.Debugw("tx expired, setting for retry..", "txID", unconfirmedTx.Tx.ID, "attempt", unconfirmedTx.Tx.Attempt)

				select {
				// add tx to be rebroadcast
				case a.broadcastChan <- unconfirmedTx.Tx.ID:
				default:
					a.logger.Errorw("failed to enqueue tx for rebroadcast", "previousHash", unconfirmedTx.Hash)
				}

			}
		}
	}
}

func (a *AptosTxm) InflightCount() (int, int) {
	return len(a.broadcastChan), a.accountStore.GetTotalInflightCount()
}

func (a *AptosTxm) getSequenceNumber(client *aptos.NodeClient, address aptos.AccountAddress) (uint64, error) {
	accountInfo, err := client.Account(address)
	if err != nil {
		a.logger.Errorw("failed to fetch account data", "error", err)
		return 0, err
	}
	sequenceNumber, err := accountInfo.SequenceNumber()
	if err != nil {
		a.logger.Errorw("failed to decode sequence number", "sequenceNumberStr", accountInfo.SequenceNumberStr, "error", err)
		return 0, err
	}
	return sequenceNumber, nil
}

func (a *AptosTxm) resyncNonce(client *aptos.NodeClient, address aptos.AccountAddress) error {
	sequenceNumber, err := a.getSequenceNumber(client, address)
	if err != nil {
		return err
	}

	txStore := a.accountStore.GetTxStore(address.String())

	previousNextNonce := txStore.GetNextNonce()
	previousLastOnchainNonce := txStore.GetLastResyncedNonce()
	txStore.ResyncNonce(sequenceNumber)
	updatedNextNonce := txStore.GetNextNonce()
	updatedLastOnchainNonce := txStore.GetLastResyncedNonce()

	a.logger.Infow("resynced nonce", "sequenceNumber", sequenceNumber, "previousLastOnchainNonce", previousLastOnchainNonce, "updatedLastOnchainNonce", updatedLastOnchainNonce, "previousNextNonce", previousNextNonce, "updatedNextNonce", updatedNextNonce)

	return nil
}

func (a *AptosTxm) getLedgerTimestamp() (uint64, error) {
	nodeInfo, err := a.client.Info()
	if err != nil {
		return 0, fmt.Errorf("failed to fetch node info: %+w", err)
	}

	ledgerTimestamp := nodeInfo.LedgerTimestamp()
	if ledgerTimestamp == 0 {
		return 0, fmt.Errorf("ledgerTimestamp is 0")
	}

	// ledgerTimestamp given in nanosec
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

func (a *AptosTxm) simulateTransaction(client *aptos.NodeClient, rawTx aptos.RawTransaction, fromAddress aptos.AccountAddress, publicKey aptoscrypto.Ed25519PublicKey) (*aptosapi.UserTransaction, error) {
	// build mock signer for simulation
	signerForSimulation := &aptos.Account{Signer: &mockSimulationSigner{pubKey: publicKey}}

	attempt := 1
	var lastError error
	for attempt <= int(a.config.MaxSimulateAttempts) {
		// need to fetch latest sequence number on-chain since we could have other in-flight txs which results in an error SEQUENCE_NUMBER_TOO_NEW
		sequenceNumber, err := a.getSequenceNumber(client, fromAddress)
		if err != nil {
			a.logger.Errorw("failed to get sequence number", "error", err)
			return nil, err
		}
		rawTx.SequenceNumber = sequenceNumber

		a.logger.Debugw("simulating tx", "attempt", attempt, "sequenceNumber", sequenceNumber)
		// TODO: consider using EstimatePrioritizedGasUnitPrice(true)
		txs, err := client.SimulateTransaction(&rawTx, signerForSimulation, aptos.EstimateMaxGasAmount(true), aptos.EstimateGasUnitPrice(true))
		if err != nil {
			a.logger.Debugw("failed to simulate tx", "error", err)
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
			a.logger.Debugw("simulated tx unexpected status", "vmStatus", simulateResponse.VmStatus)
			return nil, fmt.Errorf("simulated tx unexpected status: %v", simulateResponse.VmStatus)
		}

		a.logger.Debugw("simulate tx successful", "vmStatus", simulateResponse.VmStatus, "gasUsed", simulateResponse.GasUsed, "gasUnitPrice", simulateResponse.GasUnitPrice)
		return simulateResponse, nil
	}

	return nil, fmt.Errorf("simulation attempts failed, last error: %w", lastError)

}

func getTimestampSecs() uint64 {
	return uint64(time.Now().Unix())
}
