package txm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coming-chat/go-aptos/aptosclient"
	txbuilder "github.com/coming-chat/go-aptos/transaction_builder"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/loop"
	"github.com/smartcontractkit/chainlink-common/pkg/services"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

var _ services.Service = &AptosTxm{}

type AptosTxm struct {
	logger   logger.Logger
	keystore loop.Keystore
	config   AptosTxmConfig

	broadcastChan chan *AptosTx
	accountStore  *AccountStore
	starter       utils.StartStopOnce
	done          sync.WaitGroup
	stop          chan struct{}

	client *aptosclient.RestClient
}

func New(lgr logger.Logger, keystore loop.Keystore, config AptosTxmConfig) *AptosTxm {
	return &AptosTxm{
		logger:   logger.Named(lgr, "AptosTxm"),
		keystore: keystore,
		config:   config,

		broadcastChan: make(chan *AptosTx, config.BroadcastChanSize),
		accountStore:  NewAccountStore(),
		stop:          make(chan struct{}),
	}
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

func (a *AptosTxm) GetClient() (*aptosclient.RestClient, error) {
	if a.client == nil {
		client, err := aptosclient.Dial(context.Background(), a.config.RPCUrl)
		if err != nil {
			return nil, err
		}
		a.client = client
	}
	return a.client, nil
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

func (a *AptosTxm) Enqueue(fromAddress, publicKey, function string, paramTypes []string, paramValues []any) error {
	ed25519PublicKey, err := hexToEd25519PublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key: %+w", err)
	}

	functionTokens := strings.Split(function, "::")
	if len(functionTokens) != 3 {
		return fmt.Errorf("unexpected function name, expected 3 tokens, got %d", len(functionTokens))
	}

	contractAddress := functionTokens[0]
	moduleName := functionTokens[1]
	functionName := functionTokens[2]

	typeTags := []txbuilder.TypeTag{}
	bcsValues := [][]byte{}

	if len(paramTypes) != len(paramValues) {
		return fmt.Errorf("length of types and values do not match")
	}

	for i := 0; i < len(paramTypes); i++ {
		typeName := paramTypes[i]
		typeValue := paramValues[i]

		typeTag, err := createTypeTag(typeName)
		if err != nil {
			return fmt.Errorf("failed to parse type %s: %+w", typeName, err)
		}

		bcsValue, err := createBcsValue(typeTag, typeValue)
		if err != nil {
			return fmt.Errorf("failed to serialize value %s: %+w", typeValue, err)
		}

		typeTags = append(typeTags, typeTag)
		bcsValues = append(bcsValues, bcsValue)
	}

	tx := &AptosTx{
		FromAddress:     fromAddress,
		PublicKey:       ed25519PublicKey,
		ContractAddress: contractAddress,
		ModuleName:      moduleName,
		FunctionName:    functionName,
		TypeTags:        typeTags,
		BcsValues:       bcsValues,
	}

	select {
	case a.broadcastChan <- tx:
	default:
		return fmt.Errorf("failed to enqueue transaction: %+v", tx)
	}

	return nil
}

func (a *AptosTxm) broadcastLoop() {
	defer a.done.Done()

	_, cancel := utils.ContextFromChan(a.stop)
	defer cancel()

	a.logger.Debugw("broadcastLoop: started")
	for {
		select {
		case tx := <-a.broadcastChan:
			a.signAndBroadcast(tx)

		case <-a.stop:
			a.logger.Debugw("broadcastLoop: stopped")
			return
		}
	}
}

func (a *AptosTxm) signAndBroadcast(tx *AptosTx) {
	ledgerInfo, err := a.client.LedgerInfo()
	if err != nil {
		a.logger.Errorw("failed to fetch ledger info: %+v", err)
		return
	}

	fromAddress, err := txbuilder.NewAccountAddressFromHex(tx.FromAddress)
	if err != nil {
		a.logger.Errorw("failed to convert account address: %+v", err)
		return
	}

	txStore := a.accountStore.GetTxStore(tx.FromAddress)
	if txStore == nil {
		accountData, err := a.client.GetAccount(tx.FromAddress)
		if err != nil {
			a.logger.Errorw("failed to fetch account data: %+v", err)
			return
		}
		newTxStore, err := a.accountStore.CreateTxStore(tx.FromAddress, accountData.SequenceNumber)
		if err != nil {
			a.logger.Errorw("failed to create tx store for %s: %+v", tx.FromAddress, err)
			return
		}
		txStore = newTxStore
	}

	gasPrice, err := a.client.EstimateGasPrice()
	if err != nil {
		a.logger.Errorw("failed to estimate gas price: %+v", err)
		return
	}

	moduleId, err := txbuilder.NewModuleIdFromString(tx.ContractAddress + "::" + tx.ModuleName)
	if err != nil {
		a.logger.Errorw("failed to generatee module id: %+v", err)
		return
	}

	payload := txbuilder.TransactionPayloadEntryFunction{
		ModuleName:   *moduleId,
		FunctionName: txbuilder.Identifier(tx.FunctionName),
		TyArgs:       tx.TypeTags,
		Args:         tx.BcsValues,
	}

	nonce := txStore.GetNextNonce()

	rawTx := &txbuilder.RawTransaction{
		Sender:         *fromAddress,
		SequenceNumber: nonce,
		Payload:        payload,
		// TODO: gas amount estimation? we use the default as per aptos-ts-sdk for now.
		// https://github.com/aptos-labs/aptos-ts-sdk/blob/32d4360740392782c1368647f89ba62e1b6a2cb3/src/utils/const.ts#L21
		MaxGasAmount: 200000,
		GasUnitPrice: gasPrice,
		// TODO: handle expiry
		ExpirationTimestampSecs: ledgerInfo.LedgerTimestamp + 600,
		ChainId:                 uint8(a.client.ChainId()),
	}

	builder := txbuilder.NewTransactionBuilderEd25519(func(sm txbuilder.SigningMessage) []byte {
		signature, err := a.keystore.Sign(context.Background(), tx.FromAddress, sm)
		if err != nil {
			a.logger.Errorw("failed to sign message from %s: %+v", tx.FromAddress, err)
			// return an empty signature, allow builder.Sign to fail on the next step.
			return []byte{}
		}
		return signature
	}, tx.PublicKey)

	signedTx, err := builder.Sign(rawTx)
	if err != nil {
		a.logger.Errorw("failed to sign transaction: %+v", err)
		return
	}

	clientTx, err := a.client.SubmitSignedBCSTransaction(signedTx)
	if err != nil {
		a.logger.Errorw("failed to submit signed transaction: %+v", err)
		return
	}

	a.logger.Infow("DEBUG: submitted %+v", clientTx)
	txStore.AddUnconfirmed(nonce, clientTx.Hash, uint64(time.Now().Unix()), tx)
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
	client, err := a.GetClient()
	if err != nil {
		a.logger.Errorw("failed to load client", "error", err)
		return
	}
	allUnconfirmedTxs := a.accountStore.GetAllUnconfirmed()
	for accountAddress, unconfirmedTxs := range allUnconfirmedTxs {
		for _, unconfirmedTx := range unconfirmedTxs {
			hash := unconfirmedTx.Hash

			chainTx, err := client.GetTransactionByHash(hash)
			if err != nil {
				// TODO: check expiry?
				a.logger.Errorw("failed to check for transaction", "hash", hash, "error", err)
				continue

			}

			if chainTx.Type == "pending_transaction" {
				// TODO: check expiry?
				continue
			}

			a.logger.Debugw("transaction confirmed", "hash", hash, "type", chainTx.Type)

			if err := a.accountStore.GetTxStore(accountAddress).Confirm(unconfirmedTx.Nonce, hash); err != nil {
				a.logger.Errorw("failed to confirm tx in TxStore", "hash", hash, "accountAddress", accountAddress, "error", err)
			}
		}
	}
}

func (a *AptosTxm) InflightCount() (int, int) {
	return len(a.broadcastChan), a.accountStore.GetTotalInflightCount()
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
