package client

import (
	"context"
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"golang.org/x/sync/semaphore"
	"time"
)

type RateLimitedClient interface {
	View(payload *aptos.ViewPayload) ([]any, error)
	EventsByHandle(address aptos.AccountAddress, eventHandle, fieldName string, start, limit *uint64) ([]*api.Event, error)
	Info() (aptos.NodeInfo, error)
	Account(address aptos.AccountAddress) (aptos.AccountInfo, error)
	TransactionByHash(hash string) (*api.Transaction, error)
	SubmitTransaction(signedTxn *aptos.SignedTransaction) (*api.SubmitTransactionResponse, error)
	EstimateGasPrice() (aptos.EstimateGasInfo, error)
	BlockByHeight(height uint64, withTransactions bool) (*api.Block, error)
	AccountAPTBalance(account aptos.AccountAddress, ledgerVersion ...uint64) (balance uint64, err error)
	GetChainId() (uint8, error)
	SimulateTransaction(rawTxn *aptos.RawTransaction, sender aptos.TransactionSigner, options ...any) ([]*api.UserTransaction, error)
}

type rateLimitedClient struct {
	client  *aptos.NodeClient
	sem     *semaphore.Weighted
	timeout time.Duration
}

func NewRateLimitedClient(client *aptos.NodeClient, maxConcurrent int64, timeout time.Duration) *rateLimitedClient {
	return &rateLimitedClient{
		client:  client,
		sem:     semaphore.NewWeighted(maxConcurrent),
		timeout: timeout,
	}
}

func (c *rateLimitedClient) withRateLimit(f func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	if err := c.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer c.sem.Release(1)

	return f()
}

func (c *rateLimitedClient) View(payload *aptos.ViewPayload) ([]any, error) {
	var result []any
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.View(payload)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) EventsByHandle(address aptos.AccountAddress, eventHandle, fieldName string, start, limit *uint64) ([]*api.Event, error) {
	var result []*api.Event
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.EventsByHandle(address, eventHandle, fieldName, start, limit)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) Info() (aptos.NodeInfo, error) {
	var result aptos.NodeInfo
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.Info()
		return err
	})
	return result, err
}

func (c *rateLimitedClient) Account(address aptos.AccountAddress) (aptos.AccountInfo, error) {
	var result aptos.AccountInfo
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.Account(address)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) TransactionByHash(hash string) (*api.Transaction, error) {
	var result *api.Transaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.TransactionByHash(hash)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) SubmitTransaction(signedTxn *aptos.SignedTransaction) (*api.SubmitTransactionResponse, error) {
	var result *api.SubmitTransactionResponse
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.SubmitTransaction(signedTxn)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) EstimateGasPrice() (aptos.EstimateGasInfo, error) {
	var result aptos.EstimateGasInfo
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.EstimateGasPrice()
		return err
	})
	return result, err
}

func (c *rateLimitedClient) BlockByHeight(height uint64, withTransactions bool) (*api.Block, error) {
	var result *api.Block
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BlockByHeight(height, withTransactions)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) AccountAPTBalance(account aptos.AccountAddress, ledgerVersion ...uint64) (uint64, error) {
	var result uint64
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountAPTBalance(account, ledgerVersion...)
		return err
	})
	return result, err
}

func (c *rateLimitedClient) GetChainId() (uint8, error) {
	var result uint8
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.GetChainId()
		return err
	})
	return result, err
}

func (c *rateLimitedClient) SimulateTransaction(rawTxn *aptos.RawTransaction, sender aptos.TransactionSigner, options ...any) ([]*api.UserTransaction, error) {
	var result []*api.UserTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.SimulateTransaction(rawTxn, sender, options...)
		return err
	})
	return result, err
}
