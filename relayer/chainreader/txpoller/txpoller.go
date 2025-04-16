package txpoller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/sqlutil"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

type TxPollerConfig struct {
	PollInterval  time.Duration
	initialOffset uint64

	ModuleIdentifier string
	EventIdentifier  string
}

type TxPoller struct {
	starter utils.StartStopOnce
	quit    chan struct{}

	config       TxPollerConfig
	readerConfig chainreader.ChainReaderConfig
	txOffset     uint64

	client       aptos.AptosRpcClient
	boundAddress aptos.AccountAddress
	dbStore      *chainreader.DBStore
}

func New(logger logger.Logger, client aptos.AptosRpcClient, config chainreader.ChainReaderConfig, ds sqlutil.DataSource) *TxPoller {
	// temp: hardcode for now
	tpConfig := TxPollerConfig{
		PollInterval:     10 * time.Second,
		initialOffset:    0,
		ModuleIdentifier: "offramp",
		EventIdentifier:  "ExecutionStateChanged",
	}

	var dbStore *chainreader.DBStore
	if ds != nil {
		dbStore = chainreader.NewDBStore(ds)
	}

	return &TxPoller{
		client:  client,
		dbStore: dbStore,

		config:       tpConfig,
		readerConfig: config,
		txOffset:     tpConfig.initialOffset,

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
	moduleConfig, ok := tp.readerConfig.Modules[tp.config.ModuleIdentifier]
	if !ok {
			return fmt.Errorf("failed to find module config for identifier: %s", tp.config.ModuleIdentifier)
	}

	eventConfig, ok := moduleConfig.Events[tp.config.EventIdentifier]
	if !ok {
			return fmt.Errorf("failed to find event config for identifier: %s", tp.config.EventIdentifier)
	}

	eventHandle := tp.boundAddress.String() + "::" + moduleConfig.Name + "::" + eventConfig.EventHandleStructName

	eventAccountAddress, err := cr.ComputeEventAccountAddress(tp.boundAddress, eventConfig)
	if err != nil {
			return fmt.Errorf("failed to compute event account address: %w", err)
	}

	var records []chainreader.EventRecord
	limit := uint64(25)
	for {
			txns, err := tp.client.AccountTransactions(tp.boundAddress, &tp.txOffset, &limit)
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

					head, err := cr.GetBlockHead(txn.Version())
					if err != nil {
							fmt.Printf("failed to get block head for txn version %d: %v\n", txn.Version(), err)
							continue
					}

					// todo: process payload here and contstruct event data

					record := chainreader.EventRecord{
							EventAccountAddress: eventAccountAddress.String(),
							EventHandle:         eventHandle,
							EventOffset:         userTxn.SequenceNumber,
							BlockVersion:        txn.Version(),
							BlockHeight:         head.Height,
							BlockHash:           head.Hash,
							BlockTimestamp:      head.Timestamp,
							// todoL put event data here
							Data: 						 nil,
					}
					records = append(records, record)
			}

			lastTxn := txns[len(txns)-1]
			tp.txOffset = lastTxn.Version() + 1

			if uint64(len(txns)) < limit {
					break
			}
	}

	if len(records) > 0 {
			if err := tp.dbStore.InsertEvents(ctx, records); err != nil {
					return fmt.Errorf("failed to insert events: %w", err)
			}
	}
	
	return nil
}
