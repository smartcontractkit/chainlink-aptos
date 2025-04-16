package txpoller

import (
	"context"
	"fmt"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/smartcontractkit/chainlink-aptos/relayer/chainreader"
	"github.com/smartcontractkit/chainlink-common/pkg/logger"
	"github.com/smartcontractkit/chainlink-common/pkg/utils"
)

type TxPollerConfig struct {
	PollInterval  time.Duration
	InitialOffset uint64

	EventHandle    string
	AccountAddress aptos.AccountAddress
}

type TxPoller struct {
	starter utils.StartStopOnce
	quit    chan struct{}

	config   TxPollerConfig
	txOffset uint64

	client aptos.AptosRpcClient
	ds     *chainreader.DBStore
}

func New(logger logger.Logger, client aptos.AptosRpcClient, _ TxPollerConfig, ds *chainreader.DBStore) *TxPoller {
	// temp: hardcode for now
	tpConfig := TxPollerConfig{
		PollInterval: 10 * time.Second,

		InitialOffset:  0,
		EventHandle:    "test",
		AccountAddress: aptos.AccountZero,
	}

	return &TxPoller{
		client: client,
		ds:     ds,

		config:   tpConfig,
		txOffset: tpConfig.InitialOffset,

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
		txns, err := tp.client.AccountTransactions(tp.config.AccountAddress, &tp.txOffset, &limit)
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

			// todo: get block data from tx?
			// todo: process payload here and contstruct event data

			record := chainreader.EventRecord{
				EventAccountAddress: tp.config.AccountAddress.String(),
				EventHandle:         tp.config.EventHandle,
				EventOffset:         userTxn.SequenceNumber,

				BlockVersion:   0,
				BlockHeight:    "",
				BlockHash:      nil,
				BlockTimestamp: 0,

				// todo: put event data here
				Data: nil,
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
		if err := tp.ds.InsertEvents(ctx, records); err != nil {
			return fmt.Errorf("failed to insert events: %w", err)
		}
	}

	return nil
}
