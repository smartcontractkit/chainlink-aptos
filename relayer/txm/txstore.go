package txm

import (
	"fmt"
	"sort"
	"sync"

	"golang.org/x/exp/maps"
)

type UnconfirmedTx struct {
	Nonce                   uint64
	Hash                    string
	ExpirationTimestampSecs uint64
	Tx                      *AptosTx
}

// TxStore tracks broadcast & unconfirmed txs per account address per chain id
type TxStore struct {
	lock sync.RWMutex

	nextNonce         uint64
	unconfirmedNonces map[uint64]*UnconfirmedTx
	failedNonces      map[uint64]struct{}
	lastOnchainNonce  uint64
}

func NewTxStore(initialNonce uint64) *TxStore {
	return &TxStore{
		nextNonce:         initialNonce,
		unconfirmedNonces: make(map[uint64]*UnconfirmedTx),
		failedNonces:      make(map[uint64]struct{}),
		lastOnchainNonce:  initialNonce,
	}
}

// Resync the next nonce.
// This should never be called between GetNextNonce() and AddUnconfirmed() as it
// updates the next nonce, since AddUnconfirmed expects the current `nextNonce` to be
// used for the following transaction.
func (s *TxStore) ResyncNonce(onchainNonce uint64) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove any failed nonces that are smaller, since reuse would not be possible.
	badFailedNonces := []uint64{}
	for failedNonce := range s.failedNonces {
		// if failedNonce == onchainNonce, then it would be eventually reused,
		// and it means that nextNonce is already ahead of onchainNonce.
		if failedNonce >= onchainNonce {
			continue
		}
		badFailedNonces = append(badFailedNonces, failedNonce)
	}
	for _, failedNonce := range badFailedNonces {
		delete(s.failedNonces, failedNonce)
	}

	if s.nextNonce < onchainNonce {
		// The nextNonce is smaller than the known on-chain nonce, we are out of sync.
		s.nextNonce = onchainNonce
	}

	// Cache the last known on-chain nonce, so that when Confirm() is called with a failing transaction,
	// we won't try to reuse it.
	s.lastOnchainNonce = onchainNonce
}

func (s *TxStore) GetLastResyncedNonce() uint64 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.lastOnchainNonce
}

func (s *TxStore) GetNextNonce() uint64 {
	s.lock.Lock()
	defer s.lock.Unlock()

	nextNonce := s.nextNonce
	if len(s.failedNonces) > 0 {
		for nonce := range s.failedNonces {
			nextNonce = min(nextNonce, nonce)
		}
	}

	return nextNonce
}

func (s *TxStore) AddUnconfirmed(nonce uint64, hash string, expirationTimestampSecs uint64, tx *AptosTx) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if h, exists := s.unconfirmedNonces[nonce]; exists {
		return fmt.Errorf("nonce used: tried to use nonce (%d) for tx (%s), already used by (%s)", nonce, hash, h.Hash)
	}

	if _, isFailedNonce := s.failedNonces[nonce]; !isFailedNonce {
		// this is a new nonce that we're using, which should match `nextNonce`.
		if nonce < s.nextNonce {
			return fmt.Errorf("tried to add an unconfirmed tx at an old nonce: expected %d, got %d", s.nextNonce, nonce)
		}
		if nonce > s.nextNonce {
			return fmt.Errorf("tried to add an unconfirmed tx at a future nonce: expected %d, got %d", s.nextNonce, nonce)
		}

		s.nextNonce = s.nextNonce + 1
	} else {
		delete(s.failedNonces, nonce)
	}

	s.unconfirmedNonces[nonce] = &UnconfirmedTx{
		Nonce:                   nonce,
		Hash:                    hash,
		ExpirationTimestampSecs: expirationTimestampSecs,
		Tx:                      tx,
	}

	return nil
}

func (s *TxStore) Confirm(nonce uint64, hash string, failed bool) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	unconfirmed, exists := s.unconfirmedNonces[nonce]
	if !exists {
		return fmt.Errorf("no such unconfirmed nonce: %d", nonce)
	}
	// sanity check that the hash matches
	if unconfirmed.Hash != hash {
		return fmt.Errorf("unexpected tx hash: expected %s, got %s", unconfirmed.Hash, hash)
	}
	delete(s.unconfirmedNonces, nonce)

	if failed && nonce >= s.lastOnchainNonce {
		s.failedNonces[nonce] = struct{}{}
	}
	return nil
}

func (s *TxStore) GetUnconfirmed() []*UnconfirmedTx {
	s.lock.RLock()
	defer s.lock.RUnlock()

	unconfirmed := maps.Values(s.unconfirmedNonces)
	result := make([]*UnconfirmedTx, len(unconfirmed))

	for i, tx := range unconfirmed {
		// create a shallow copy with the same fields
		// note: still sharing the same tx pointer,
		// accessing underlying AptosTx must be synchronized
		result[i] = &UnconfirmedTx{
			Nonce:                   tx.Nonce,
			Hash:                    tx.Hash,
			ExpirationTimestampSecs: tx.ExpirationTimestampSecs,
			Tx:                      tx.Tx,
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Nonce < result[j].Nonce
	})

	return result
}

func (s *TxStore) InflightCount() int {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return len(s.unconfirmedNonces)
}

type AccountStore struct {
	store map[string]*TxStore // map account address to txstore
	lock  sync.RWMutex
}

func NewAccountStore() *AccountStore {
	return &AccountStore{
		store: map[string]*TxStore{},
	}
}

func (c *AccountStore) CreateTxStore(accountAddress string, initialNonce uint64) (*TxStore, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, ok := c.store[accountAddress]
	if ok {
		return nil, fmt.Errorf("TxStore already exists: %s", accountAddress)
	}
	store := NewTxStore(initialNonce)
	c.store[accountAddress] = store
	return store, nil
}

// GetTxStore returns the TxStore for the provided account.
func (c *AccountStore) GetTxStore(accountAddress string) *TxStore {
	c.lock.RLock()
	defer c.lock.RUnlock()
	store, ok := c.store[accountAddress]
	if !ok {
		return nil
	}
	return store
}

func (c *AccountStore) GetTotalInflightCount() int {
	c.lock.RLock()
	defer c.lock.RUnlock()

	count := 0
	for _, store := range c.store {
		count += store.InflightCount()
	}

	return count
}

func (c *AccountStore) GetAllUnconfirmed() map[string][]*UnconfirmedTx {
	c.lock.RLock()
	defer c.lock.RUnlock()

	allUnconfirmed := map[string][]*UnconfirmedTx{}
	for accountAddress, store := range c.store {
		allUnconfirmed[accountAddress] = store.GetUnconfirmed()
	}
	return allUnconfirmed
}
