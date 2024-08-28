package txm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	aptosapi "github.com/aptos-labs/aptos-go-sdk/api"
	aptoscrypto "github.com/aptos-labs/aptos-go-sdk/crypto"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	commontypes "github.com/smartcontractkit/chainlink-common/pkg/types"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

var _ services.Service = &AptosTxm{}

// https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21
const DEFAULT_MAX_GAS_AMOUNT = 200000
const MAX_SIMULATE_ATTEMPTS = 5

// todo: add to txm config?
const MAX_SUBMIT_RETRY_ATTEMPTS = 5
const SUBMIT_DELAY_DURATION = 5 // seconds
const TX_EXPIRATION_TIME = 600  // seconds
const MAX_TX_RETRY_ATTEMPTS = 2

type AptosTxm struct {
	logger   logger.Logger
	keystore loop.Keystore
	config   AptosTxmConfig

	transactions     map[string]*AptosTx
	transactionsLock sync.RWMutex

	broadcastChan chan string
	accountStore  *AccountStore
	starter       utils.StartStopOnce
	done          sync.WaitGroup
	stop          chan struct{}

	client *aptos.NodeClient
}

func New(lgr logger.Logger, keystore loop.Keystore, config AptosTxmConfig, getClient func() (*aptos.NodeClient, error)) (*AptosTxm, error) {
	client, err := getClient()
	if err != nil {
		return nil, err
	}

	return &AptosTxm{
		logger:   logger.Named(lgr, "AptosTxm"),
		keystore: keystore,
		config:   config,
		client:   client,

		transactions: map[string]*AptosTx{},

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
			return nil
		}
	}

	ed25519PublicKey, err := hexToEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %+w", err)
	}

	if fromAddress == "" {
		// If the address is not specified, we assume the public key is for its corresponding address
		// and not for an address with a rotated authentication key.
		authKey := sha3.Sum256(append([]byte(ed25519PublicKey), 0x00))
		accountAddress := aptos.AccountAddress(authKey)
		fromAddress = accountAddress.String()
	}

	a.logger.Debugw("Tx enqueued", "txID", transactionID, "fromAddr", fromAddress)

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

	tx := &AptosTx{
		ID: transactionID,
		// TODO: clean up old transactions in the map by timestamp.
		Timestamp:       uint64(time.Now().Unix()),
		FromAddress:     *fromAccountAddress,
		PublicKey:       ed25519PublicKey,
		ContractAddress: *contractAccountAddress,
		ModuleName:      moduleName,
		FunctionName:    functionName,
		TypeTags:        typeTags,
		BcsValues:       bcsValues,
		Status:          commontypes.Unconfirmed,
		Simulate:        simulateTx,
	}

	a.transactionsLock.Lock()
	a.transactions[transactionID] = tx
	a.transactionsLock.Unlock()

	select {
	case a.broadcastChan <- transactionID:
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
		case transactionID := <-a.broadcastChan:
			a.transactionsLock.Lock()
			tx, ok := a.transactions[transactionID]
			a.transactionsLock.Unlock()
			if !ok {
				a.logger.Errorw("failed to find tx", "txID", transactionID)
				continue
			}
			a.signAndBroadcast(tx)

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
		tx.Status = commontypes.Fatal
		return
	}

	txStore := a.accountStore.GetTxStore(tx.FromAddress.String())
	if txStore == nil {
		sequenceNumber, err := a.getSequenceNumber(client, tx.FromAddress)
		if err != nil {
			a.logger.Errorw("failed to get sequence number", "error", err)
			tx.Status = commontypes.Fatal
			return
		}
		newTxStore, err := a.accountStore.CreateTxStore(tx.FromAddress.String(), sequenceNumber)
		if err != nil {
			a.logger.Errorw("failed to create tx store", "fromAddress", tx.FromAddress, "error", err)
			tx.Status = commontypes.Fatal
			return
		}
		txStore = newTxStore
	}

	nodeInfo, err := client.Info()
	if err != nil {
		a.logger.Errorw("failed to fetch ledger info", "error", err)
		tx.Status = commontypes.Fatal
		return
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

	buildSignedTx := func() (*aptos.SignedTransaction, uint64, error) {
		nonce := txStore.GetNextNonce()

		ledgerTimestamp := nodeInfo.LedgerTimestamp()
		if ledgerTimestamp == 0 {
			a.logger.Errorw("failed to fetch ledger timestamp", "nodeInfo", nodeInfo)
			return nil, nonce, errors.New("failed to fetch ledger timestamp")
		}

		rawTx := aptos.RawTransaction{
			Sender:                     tx.FromAddress,
			SequenceNumber:             nonce,
			Payload:                    payload,
			MaxGasAmount:               0,                                                    // populated below
			GasUnitPrice:               0,                                                    // populated below
			ExpirationTimestampSeconds: ledgerTimestamp/1000000 + uint64(TX_EXPIRATION_TIME), // ledgerTimestamp returned in nanosec
			ChainId:                    chainId,
		}

		publicKey := aptoscrypto.Ed25519PublicKey{}
		err = publicKey.FromBytes([]byte(tx.PublicKey))
		if err != nil {
			a.logger.Errorw("failed to deserialize public key", "error", err)
			return nil, nonce, err
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
				return nil, nonce, err
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
			rawTx.MaxGasAmount = DEFAULT_MAX_GAS_AMOUNT
			a.logger.Debugw("using default max gas amount", "maxGasAmount", DEFAULT_MAX_GAS_AMOUNT)
		}

		signingMessage, err := rawTx.SigningMessage()
		if err != nil {
			a.logger.Errorw("failed to create signing message", "error", err)
			return nil, nonce, err
		}

		signature, err := a.keystore.Sign(context.Background(), fmt.Sprintf("%064x", tx.PublicKey), signingMessage)
		if err != nil {
			a.logger.Errorw("failed to sign message", "fromAddress", tx.FromAddress, "error", err)
			return nil, nonce, err
		}

		sig := aptoscrypto.Ed25519Signature{}
		err = sig.FromBytes(signature)
		if err != nil {
			a.logger.Errorw("failed to deserialize signature", "error", err)
			return nil, nonce, err
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
			return nil, nonce, err
		}

		return signedTx, nonce, nil
	}

	// broadcast with basic retry to try get the tx included in the mempool
	attempt := 1
	for attempt <= MAX_SUBMIT_RETRY_ATTEMPTS {
		// rebuild the tx to update the nonce and expiration timestamp
		signedTx, nonce, err := buildSignedTx()
		if err != nil {
			a.logger.Errorw("failed to build signed tx", "error", err)
			tx.Status = commontypes.Fatal
			return
		}

		submitResponse, err := client.SubmitTransaction(signedTx)
		if err != nil {
			var httpErr *aptos.HttpError
			if errors.As(err, &httpErr) {
				// In case of http errors (>400) wait gracefully and retry
				// It inlcudes all network-related errors as well as
				// the pre-execution validation in the Mempool (e.g. old/duplicated nonce)
				a.logger.Errorw("failed to submit signed tx, retrying..", "error", httpErr)
				time.Sleep(SUBMIT_DELAY_DURATION * time.Second)
				attempt++
				continue
			} else {
				// Do not retry on unknown errors
				a.logger.Errorw("failed to submit signed tx, aborting..", "error", err)
				tx.Status = commontypes.Fatal
				break
			}
		} else {
			// Tx included in the Mempool
			a.logger.Debugw("submit tx successful", "submitResponse", submitResponse)

			if submitResponse.Hash == "" {
				a.logger.Errorw("did not receive hash after successful tx submission", "txID", tx.ID)
				tx.Status = commontypes.Fatal
				return
			} else {
				err = txStore.AddUnconfirmed(nonce, submitResponse.Hash, uint64(time.Now().Unix()), tx)
				if err != nil {
					// TODO: figure out what to do here.
					a.logger.Errorw("failed to add unconfirmed tx", "txHash", submitResponse.Hash, "error", err)
					tx.Status = commontypes.Fatal
				}
			}
			return
		}
	}

	if err != nil {
		a.logger.Errorw("reached max retries for submitting the tx", "txID", tx.ID)
	}
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

	nodeInfo, err := client.Info()
	if err != nil {
		a.logger.Errorw("failed to fetch ledger info", "error", err)
		return
	}

	ledgerTimestampInSec := nodeInfo.LedgerTimestamp() / 1000000
	allUnconfirmedTxs := a.accountStore.GetAllUnconfirmed()

	for accountAddress, unconfirmedTxs := range allUnconfirmedTxs {
		for _, unconfirmedTx := range unconfirmedTxs {
			hash := unconfirmedTx.Hash

			chainTx, err := client.TransactionByHash(hash)
			if err != nil || chainTx.Type == aptosapi.TransactionVariantPending {
				if ledgerTimestampInSec > unconfirmedTx.Timestamp+TX_EXPIRATION_TIME {
					// LedgerTimestamp dictates expiration, the local node might lag behind
					// At this point we know the tx won't be committed
					a.logger.Debugw("tx expired, setting for retry..", "txID", unconfirmedTx.Tx.ID, "hash", hash)
					unconfirmedTx.Tx.Status = commontypes.Failed

					// Confirm tx to remove it from the unconfirmedNonces pool
					// On retry the tx will get the new hash and reenter the pool for further tracking
					err = a.accountStore.GetTxStore(accountAddress).Confirm(unconfirmedTx.Nonce, hash)
					if err != nil {
						a.logger.Errorw("coudln't confirm expired tx", "error", err)
						continue
					}

					unconfirmedTx.Tx.Attempt++
					if unconfirmedTx.Tx.Attempt > MAX_TX_RETRY_ATTEMPTS {
						unconfirmedTx.Tx.Status = commontypes.Fatal
						a.logger.Errorw("tx reached max num of retries and will be discarded", "txID", unconfirmedTx.Tx.ID, "hash", hash)
						continue
					}

					select {
					case a.broadcastChan <- unconfirmedTx.Tx.ID:
					default:
						a.logger.Errorw("failed to enqueue retry tx", "previousHash", unconfirmedTx.Hash)
					}
				} else {
					a.logger.Debugw("tx not found or pending in the mempool", "hash", hash)
				}

				continue
			}

			a.logger.Debugw("tx confirmed", "txID", unconfirmedTx.Tx.ID, "hash", hash, "type", chainTx.Type)
			unconfirmedTx.Tx.Status = commontypes.Finalized

			if err := a.accountStore.GetTxStore(accountAddress).Confirm(unconfirmedTx.Nonce, hash); err != nil {
				a.logger.Errorw("failed to confirm tx in TxStore", "hash", hash, "accountAddress", accountAddress, "error", err)
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
	for attempt <= MAX_SIMULATE_ATTEMPTS {
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

func hexToEd25519PublicKey(hexKey string) (ed25519.PublicKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %v", err)
	}

	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key length: %d bytes, expected %d bytes", len(keyBytes), ed25519.PublicKeySize)
	}

	publicKey := ed25519.PublicKey(keyBytes)
	return publicKey, nil
}
