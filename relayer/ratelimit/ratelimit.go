package ratelimit

import (
	"context"
	"time"

	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/api"
	"golang.org/x/sync/semaphore"
)

type rateLimitedClient struct {
	client  *aptos.NodeClient
	sem     *semaphore.Weighted
	timeout time.Duration
}

var _ aptos.AptosRpcClient = &rateLimitedClient{}

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

func (c *rateLimitedClient) View(payload *aptos.ViewPayload, ledgerVersion ...uint64) ([]any, error) {
	var result []any
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.View(payload, ledgerVersion...)
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

func (c *rateLimitedClient) EventsByCreationNumber(
	account aptos.AccountAddress,
	creationNumber string,
	start *uint64,
	limit *uint64,
) ([]*api.Event, error) {
	var result []*api.Event
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.EventsByCreationNumber(account, creationNumber, start, limit)
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

func (c *rateLimitedClient) Account(address aptos.AccountAddress, ledgerVersion ...uint64) (aptos.AccountInfo, error) {
	var result aptos.AccountInfo
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.Account(address, ledgerVersion...)
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

// SetTimeout adjusts the HTTP client timeout
func (c *rateLimitedClient) SetTimeout(timeout time.Duration) {
	c.client.SetTimeout(timeout)
}

// SetHeader sets the header for all future requests
func (c *rateLimitedClient) SetHeader(key string, value string) {
	c.client.SetHeader(key, value)
}

// RemoveHeader removes the header from being automatically set for all future requests
func (c *rateLimitedClient) RemoveHeader(key string) {
	c.client.RemoveHeader(key)
}

// AccountResource retrieves a single resource given its struct name
func (c *rateLimitedClient) AccountResource(address aptos.AccountAddress, resourceType string, ledgerVersion ...uint64) (map[string]any, error) {
	var result map[string]any
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountResource(address, resourceType, ledgerVersion...)
		return err
	})
	return result, err
}

// AccountResources fetches resources for an account
func (c *rateLimitedClient) AccountResources(address aptos.AccountAddress, ledgerVersion ...uint64) ([]aptos.AccountResourceInfo, error) {
	var result []aptos.AccountResourceInfo
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountResources(address, ledgerVersion...)
		return err
	})
	return result, err
}

// AccountResourcesBCS fetches account resources as raw Move struct BCS blobs
func (c *rateLimitedClient) AccountResourcesBCS(address aptos.AccountAddress, ledgerVersion ...uint64) ([]aptos.AccountResourceRecord, error) {
	var result []aptos.AccountResourceRecord
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountResourcesBCS(address, ledgerVersion...)
		return err
	})
	return result, err
}

// AccountModule fetches a single account module's bytecode and ABI from on-chain state
func (c *rateLimitedClient) AccountModule(address aptos.AccountAddress, moduleName string, ledgerVersion ...uint64) (*api.MoveBytecode, error) {
	var result *api.MoveBytecode
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountModule(address, moduleName, ledgerVersion...)
		return err
	})
	return result, err
}

// EntryFunctionWithArgs generates an EntryFunction from on-chain Module ABI
func (c *rateLimitedClient) EntryFunctionWithArgs(moduleAddress aptos.AccountAddress, moduleName string, functionName string, typeArgs []any, args []any) (*aptos.EntryFunction, error) {
	var result *aptos.EntryFunction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.EntryFunctionWithArgs(moduleAddress, moduleName, functionName, typeArgs, args)
		return err
	})
	return result, err
}

// BlockByVersion fetches a block by ledger version
func (c *rateLimitedClient) BlockByVersion(ledgerVersion uint64, withTransactions bool) (*api.Block, error) {
	var result *api.Block
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BlockByVersion(ledgerVersion, withTransactions)
		return err
	})
	return result, err
}

// WaitTransactionByHash waits for a transaction to be confirmed by its hash
func (c *rateLimitedClient) WaitTransactionByHash(txnHash string) (*api.Transaction, error) {
	var result *api.Transaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.WaitTransactionByHash(txnHash)
		return err
	})
	return result, err
}

// TransactionByVersion gets info on a transaction from its LedgerVersion
func (c *rateLimitedClient) TransactionByVersion(version uint64) (*api.CommittedTransaction, error) {
	var result *api.CommittedTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.TransactionByVersion(version)
		return err
	})
	return result, err
}

// PollForTransaction waits for a transaction to be done
func (c *rateLimitedClient) PollForTransaction(hash string, options ...any) (*api.UserTransaction, error) {
	var result *api.UserTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.PollForTransaction(hash, options...)
		return err
	})
	return result, err
}

// PollForTransactions waits for multiple transactions to be done
func (c *rateLimitedClient) PollForTransactions(txnHashes []string, options ...any) error {
	return c.withRateLimit(func() error {
		return c.client.PollForTransactions(txnHashes, options...)
	})
}

// WaitForTransaction does a long-GET for one transaction and waits for it to complete
func (c *rateLimitedClient) WaitForTransaction(txnHash string, options ...any) (*api.UserTransaction, error) {
	var result *api.UserTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.WaitForTransaction(txnHash, options...)
		return err
	})
	return result, err
}

// Transactions gets recent transactions
func (c *rateLimitedClient) Transactions(start *uint64, limit *uint64) ([]*api.CommittedTransaction, error) {
	var result []*api.CommittedTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.Transactions(start, limit)
		return err
	})
	return result, err
}

// AccountTransactions gets transactions associated with an account
func (c *rateLimitedClient) AccountTransactions(address aptos.AccountAddress, start *uint64, limit *uint64) ([]*api.CommittedTransaction, error) {
	var result []*api.CommittedTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.AccountTransactions(address, start, limit)
		return err
	})
	return result, err
}

// BatchSubmitTransaction submits a collection of signed transactions to the network in a single request
func (c *rateLimitedClient) BatchSubmitTransaction(signedTxns []*aptos.SignedTransaction) (*api.BatchSubmitTransactionResponse, error) {
	var result *api.BatchSubmitTransactionResponse
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BatchSubmitTransaction(signedTxns)
		return err
	})
	return result, err
}

// SimulateTransactionMultiAgent simulates a transaction as fee payer or multi agent
func (c *rateLimitedClient) SimulateTransactionMultiAgent(rawTxn *aptos.RawTransactionWithData, sender aptos.TransactionSigner, options ...any) ([]*api.UserTransaction, error) {
	var result []*api.UserTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.SimulateTransactionMultiAgent(rawTxn, sender, options...)
		return err
	})
	return result, err
}

// BuildTransaction builds a raw transaction from the payload and fetches any necessary information from on-chain
func (c *rateLimitedClient) BuildTransaction(sender aptos.AccountAddress, payload aptos.TransactionPayload, options ...any) (*aptos.RawTransaction, error) {
	var result *aptos.RawTransaction
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BuildTransaction(sender, payload, options...)
		return err
	})
	return result, err
}

// BuildTransactionMultiAgent builds a raw transaction for MultiAgent or FeePayer
func (c *rateLimitedClient) BuildTransactionMultiAgent(sender aptos.AccountAddress, payload aptos.TransactionPayload, options ...any) (*aptos.RawTransactionWithData, error) {
	var result *aptos.RawTransactionWithData
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BuildTransactionMultiAgent(sender, payload, options...)
		return err
	})
	return result, err
}

// BuildSignAndSubmitTransaction is a convenience function to do all three in one
func (c *rateLimitedClient) BuildSignAndSubmitTransaction(sender aptos.TransactionSigner, payload aptos.TransactionPayload, options ...any) (*api.SubmitTransactionResponse, error) {
	var result *api.SubmitTransactionResponse
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.BuildSignAndSubmitTransaction(sender, payload, options...)
		return err
	})
	return result, err
}

// NodeAPIHealthCheck checks if the node is within durationSecs of the current time
func (c *rateLimitedClient) NodeAPIHealthCheck(durationSecs ...uint64) (api.HealthCheckResponse, error) {
	var result api.HealthCheckResponse
	err := c.withRateLimit(func() error {
		var err error
		result, err = c.client.NodeAPIHealthCheck(durationSecs...)
		return err
	})
	return result, err
}
