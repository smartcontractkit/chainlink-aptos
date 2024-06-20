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

	checker := TransmitCheckerSpec{}
	if simulateTx {
		checker.CheckerType = TransmitCheckerTypeSimulate
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
		Checker:         checker,
	}

	a.transactionsLock.Lock()
	a.transactions[transactionID] = tx
	a.transactionsLock.Unlock()

	select {
	case a.broadcastChan <- transactionID:
	default:
		return fmt.Errorf("failed to enqueue transaction: %+v", tx)
	}

	return nil
}

func (a *AptosTxm) GetStatus(transactionID string) (commontypes.TransactionStatus, error) {
	if transactionID == "" {
		return commontypes.Unknown, errors.New("nil transaction id")
	}

	a.transactionsLock.Lock()
	defer a.transactionsLock.Unlock()
	tx, ok := a.transactions[transactionID]
	if !ok {
		return commontypes.Unknown, errors.New("no such transaction")
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
				a.logger.Errorw("failed to find transaction", "transactionID", transactionID)
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

	gasInfo, err := client.EstimateGasPrice()
	if err != nil {
		a.logger.Errorw("failed to retrieve estimated gas price", "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	nodeInfo, err := client.Info()
	if err != nil {
		a.logger.Errorw("failed to fetch ledger info", "error", err)
		tx.Status = commontypes.Fatal
		return
	}
	ledgerTimestamp := nodeInfo.LedgerTimestamp()
	if ledgerTimestamp == 0 {
		a.logger.Errorw("failed to fetch ledger timestamp", "nodeInfo", nodeInfo)
		tx.Status = commontypes.Fatal
		return
	}

	moduleId := aptos.ModuleId{
		Address: tx.ContractAddress,
		Name:    tx.ModuleName,
	}

	payload := aptos.TransactionPayload{
		Payload: &aptos.EntryFunction{
			Module:   moduleId,
			Function: tx.FunctionName,
			ArgTypes: tx.TypeTags,
			Args:     tx.BcsValues,
		},
	}

	nonce := txStore.GetNextNonce()

	rawTx := aptos.RawTransaction{
		Sender:         tx.FromAddress,
		SequenceNumber: nonce,
		Payload:        payload,
		MaxGasAmount:   DEFAULT_MAX_GAS_AMOUNT,
		// TODO: on retry, consider using PrioritizedGasEstimate
		GasUnitPrice: gasInfo.GasEstimate,
		// TODO: handle expiry
		ExpirationTimestampSeconds: ledgerTimestamp + uint64(600),
		ChainId:                    chainId,
	}

	publicKey := aptoscrypto.Ed25519PublicKey{}
	err = publicKey.FromBytes([]byte(tx.PublicKey))
	if err != nil {
		a.logger.Errorw("failed to deserialize public key", "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	// (if enabled for tx) simulate tx to estimate gas
	if tx.Checker.CheckerType == TransmitCheckerTypeSimulate {
		estimatedGas, err := a.estimateGas(client, rawTx, fromAddress, publicKey)
		if err != nil {
			// do not error on failed estimate gas as it could fail due to conflicting in-flight txs
			a.logger.Infow("failed to estimate gas, using default max gas amount", "maxGasAmount", DEFAULT_MAX_GAS_AMOUNT, "error", err)
		} else {
			rawTx.MaxGasAmount = estimatedGas
		}
	}

	signingMessage, err := rawTx.SigningMessage()
	if err != nil {
		a.logger.Errorw("failed to create signing message", "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	signature, err := a.keystore.Sign(context.Background(), fmt.Sprintf("%064x", tx.PublicKey), signingMessage)
	if err != nil {
		a.logger.Errorw("failed to sign message", "fromAddress", tx.FromAddress, "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	sig := aptoscrypto.Ed25519Signature{}
	err = sig.FromBytes(signature)
	if err != nil {
		a.logger.Errorw("failed to deserialize signature", "error", err)
		tx.Status = commontypes.Fatal
		return
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
		a.logger.Errorw("failed to sign transaction", "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	submitResponse, err := client.SubmitTransaction(signedTx)
	if err != nil {
		a.logger.Errorw("failed to submit signed transaction", "error", err)
		tx.Status = commontypes.Fatal
		return
	}

	a.logger.Debugw("submitted tx", "submitResponse", submitResponse)

	err = txStore.AddUnconfirmed(nonce, submitResponse.Hash, uint64(time.Now().Unix()), tx)
	if err != nil {
		// TODO: figure out what to do here.
		a.logger.Errorw("failed to add unconfirmed tx", "txHash", submitResponse.Hash, "error", err)
		tx.Status = commontypes.Fatal
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
	allUnconfirmedTxs := a.accountStore.GetAllUnconfirmed()
	for accountAddress, unconfirmedTxs := range allUnconfirmedTxs {
		for _, unconfirmedTx := range unconfirmedTxs {
			hash := unconfirmedTx.Hash

			chainTx, err := client.TransactionByHash(hash)
			if err != nil {
				// TODO: check expiry?
				a.logger.Errorw("failed to check for transaction", "hash", hash, "error", err)
				continue
			}

			if chainTx.Type == aptosapi.TransactionVariantPendingTransaction {
				// TODO: check expiry?
				continue
			}

			a.logger.Debugw("transaction confirmed", "hash", hash, "type", chainTx.Type)

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

func (key *mockSimulationSigner) PubKey() aptoscrypto.PublicKey {
	return &key.pubKey
}

func (a *AptosTxm) estimateGas(client *aptos.NodeClient, rawTx aptos.RawTransaction, fromAddress *aptos.AccountAddress, publicKey aptoscrypto.Ed25519PublicKey) (uint64, error) {
	// build mock signer for simulation
	signerForSimulation := &aptos.Account{Signer: &mockSimulationSigner{pubKey: publicKey}}

	var gasUsed uint64
	attempt := 1
	for attempt <= MAX_SIMULATE_ATTEMPTS {
		// need to fetch latest sequence number on-chain since we could have other in-flight txs which results in an error SEQUENCE_NUMBER_TOO_NEW
		sequenceNumber, err := a.getSequenceNumber(client, *fromAddress)
		if err != nil {
			a.logger.Errorw("failed to get sequence number", "error", err)
			return 0, err
		}
		rawTx.SequenceNumber = sequenceNumber

		simulateTxResp, err := client.SimulateTransaction(&rawTx, any(signerForSimulation).(aptos.TransactionSigner), aptos.EstimateMaxGasAmount(true))
		if err != nil {
			a.logger.Debugw("failed to simulate transaction", "error", err)
			return 0, err
		}
		if !*(simulateTxResp[0].TxnSuccess()) {
			if (simulateTxResp)[0].VmStatus == "SEQUENCE_NUMBER_TOO_OLD" {
				// race condition with tx confirmation incrementing the sequence number, retry
				attempt++
				continue
			}
			a.logger.Debugw("simulated transaction not successful", "vmStatus", simulateTxResp[0].VmStatus)
			return 0, fmt.Errorf("simulated transaction not successful: %v", simulateTxResp[0].VmStatus)
		}
		gasUsed = simulateTxResp[0].GasUsed
	}

	// todo: configurable multiplier?
	// fixed multiplier of 1.25 to account for potential discrepancies in gas estimation
	return uint64(float64(gasUsed) * 1.25), nil
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
