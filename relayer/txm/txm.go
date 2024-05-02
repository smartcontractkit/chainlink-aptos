package txm

import (
	"context"
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
		accountStore:  newAccountStore(),
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

func (a *AptosTxm) Enqueue(fromAddress, function string, paramTypes []string, paramValues []any) error {
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
			fmt.Printf("tx: %+v\n", tx)

		case <-a.stop:
			a.logger.Debugw("broadcastLoop: stopped")
			return
		}
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
	// TODO
}

func (a *AptosTxm) InflightCount() (int, int) {
	return len(a.broadcastChan), a.accountStore.GetTotalInflightCount()
}
