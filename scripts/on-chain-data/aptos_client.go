package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

type CoinResponse struct {
	Data struct {
		Coin struct {
			Value string `json:"value"`
		} `json:"coin"`
	} `json:"data"`
}

type Transaction struct {
	Version                 string    `json:"version"`
	Hash                    string    `json:"hash"`
	StateChangeHash         string    `json:"state_change_hash"`
	EventRootHash           string    `json:"event_root_hash"`
	StateCheckpointHash     string    `json:"state_checkpoint_hash"`
	GasUsed                 string    `json:"gas_used"`
	Success                 bool      `json:"success"`
	VMStatus                string    `json:"vm_status"`
	AccumulatorRootHash     string    `json:"accumulator_root_hash"`
	Sender                  string    `json:"sender"`
	SequenceNumber          string    `json:"sequence_number"`
	MaxGasAmount            string    `json:"max_gas_amount"`
	GasUnitPrice            string    `json:"gas_unit_price"`
	ExpirationTimestampSecs string    `json:"expiration_timestamp_secs"`
	Timestamp               string    `json:"timestamp"`
	Type                    string    `json:"type"`
	Events                  []Event   `json:"events"`
	Payload                 Payload   `json:"payload"`
	Signature               Signature `json:"signature"`
}

type Event struct {
	SequenceNumber string                 `json:"sequence_number"`
	Type           string                 `json:"type"`
	Data           map[string]interface{} `json:"data"`
}

type Payload struct {
	Type          string        `json:"type"`
	Function      string        `json:"function"`
	TypeArguments []string      `json:"type_arguments"`
	Arguments     []interface{} `json:"arguments"`
}

type Signature struct {
	Type      string `json:"type"`
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

func GetAccountBalanceByEnvironment(account string, environment string) (int64, error) {
	var coinResponse CoinResponse

	baseURL := GetAptosAPIBaseURL(environment)
	url := fmt.Sprintf("%s/accounts/%s/resource/0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>", baseURL, account)

	resp, err := http.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status code %d for account %s", resp.StatusCode, account)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	if err := json.Unmarshal(body, &coinResponse); err != nil {
		return 0, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	balance, err := strconv.ParseInt(coinResponse.Data.Coin.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing coin balance: %s", err)
	}

	return balance, nil
}

func fetchAllTransactionsFromAccount(account string, environment string) ([]Transaction, error) {
	const limit = 100
	var allTransactions []Transaction
	offset := 0

	for {
		transactions, err := fetchTransactionsPageFromAccountWithLimitAndOffset(account, environment, limit, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch page: %w", err)
		}

		if len(transactions) == 0 {
			break
		}

		allTransactions = append(allTransactions, transactions...)
		offset += len(transactions)
	}

	return allTransactions, nil
}

// Offset = 0 starts from the first transaction in the account and it's not possible to order desc
func fetchTransactionsPageFromAccountWithLimitAndOffset(account string, environment string, limit, offset int) ([]Transaction, error) {
	baseURL := GetAptosAPIBaseURL(environment)
	url := fmt.Sprintf("%s/accounts/%s/transactions?limit=%d&start=%d", baseURL, account, limit, offset)

	return fetchTransactionsPageFromAccountInternal(url)
}

func fetchMostRecentTransactionsFromAccountt(account string, environment string) ([]Transaction, error) {
	baseURL := GetAptosAPIBaseURL(environment)
	url := fmt.Sprintf("%s/accounts/%s/transactions?limit=100", baseURL, account)

	return fetchTransactionsPageFromAccountInternal(url)
}

func fetchTransactionsPageFromAccountInternal(url string) ([]Transaction, error) {
	var transactions []Transaction
	for {
		log.Printf("fetching transactions with url: %s\n", url)

		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to make request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			log.Printf("Rate limited (429) encountered. Retrying after delay...")
			time.Sleep(30 * time.Second) // Adjust retry delay as needed
			continue
		} else if resp.StatusCode == http.StatusNotFound {
			log.Printf("API call responeded with not found")
			return transactions, nil
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		if err := json.Unmarshal(body, &transactions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
		}

		return transactions, nil
	}
}
