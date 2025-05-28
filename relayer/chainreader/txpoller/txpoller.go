package txpoller

import (
	"context"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"

	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

type TxPollerConfig struct {
	PollInterval  time.Duration
	InitialSequenceNumber uint64

	EventHandle    string
	AccountAddress aptos.AccountAddress
	FunctionName   string
}

type TxPoller struct {
	starter utils.StartStopOnce
	quit    chan struct{}

	config   TxPollerConfig
	sequenceNumber uint64

	client aptos.AptosRpcClient
	ds     *chainreader.DBStore
}

func New(logger logger.Logger, client aptos.AptosRpcClient, _ TxPollerConfig, ds *chainreader.DBStore) *TxPoller {
	accAddress := &aptos.AccountAddress{}
	_ = accAddress.ParseStringRelaxed("0xc084ae8dd56ce0e949324ea9ee5f01be64b1bf70e48a4f239c82ee40d7f03421")
	tpConfig := TxPollerConfig{
		PollInterval: 10 * time.Second,

		InitialSequenceNumber:  0,
		EventHandle:    "test",
		AccountAddress: *accAddress,
		FunctionName: "0x1dd8925f10ca7b828b86a7b6bc8509ad02867577cc90f49033dcd6594bba1576::offramp::execute",
	}

	return &TxPoller{
		client: client,
		ds:     ds,

		config:   tpConfig,
		sequenceNumber: tpConfig.InitialSequenceNumber,

		quit: make(chan struct{}),
	}
}

func (tp *TxPoller) Start(ctx context.Context) error {
	return tp.starter.StartOnce("TxPoller", func() error {
		go tp.run(ctx)
		return nil
	})
}

func (tp *TxPoller) Stop() error {
	return tp.starter.StopOnce("TxPoller", func() error {
		close(tp.quit)
		return nil
	})
}

func (tp *TxPoller) run(ctx context.Context) {
	ticker := time.NewTicker(tp.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := tp.poll(ctx); err != nil {
				fmt.Printf("txpoller poll error: %v\n", err)
			}
		case <-tp.quit:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (tp *TxPoller) poll(ctx context.Context) error {
	var records []chainreader.EventRecord
	limit := uint64(25)
	
	for {
		txns, err := tp.client.AccountTransactions(tp.config.AccountAddress, &tp.sequenceNumber, &limit)
		if err != nil {
			return fmt.Errorf("failed to fetch account transactions: %w", err)
		}

		if len(txns) == 0 {
			break
		}

		for _, txn := range txns {
			userTxn, err := txn.UserTransaction()
			if err != nil {
				continue
			}

			if userTxn.Success {
				continue
			}

			payload := userTxn.Payload
			if payload.Type != api.TransactionPayloadVariantEntryFunction {
				continue
			}

			entryFunc, ok := userTxn.Payload.Inner.(*api.TransactionPayloadEntryFunction)
			if !ok {
				continue
			}

			if entryFunc.Function != tp.config.FunctionName {
				continue
			}

			record := chainreader.EventRecord{
				EventAccountAddress: "",
				EventHandle:         tp.config.EventHandle,
				EventFieldName: "",
				EventOffset:         nil,
				TxVersion:           userTxn.Version,
				BlockHeight:         "",
				BlockHash:           nil,
				BlockTimestamp:      0,
				Data:                nil,
			}

			records = append(records, record)
		}

		numProcessedTxns := uint64(len(txns))
		tp.sequenceNumber += numProcessedTxns

		if len(records) > 0 {
			if err := tp.ds.InsertEvents(ctx, records); err != nil {
				return fmt.Errorf("failed to insert events: %w", err)
			}
		}
	}

	return nil
}
