package txm

import (
	"fmt"
	"sort"
	"sync"

	"golang.org/x/exp/maps"
)

type UnconfirmedTx struct {
	Nonce     uint64
	Hash      string
	Timestamp uint64
	Tx        *AptosTx
}

// TxStore tracks broadcast & unconfirmed txs per account address per chain id
type TxStore struct {
	lock sync.RWMutex

	nextNonce         uint64
	unconfirmedNonces map[uint64]*UnconfirmedTx
}

func NewTxStore(initialNonce uint64) *TxStore {
	return &TxStore{
		nextNonce:         initialNonce,
		unconfirmedNonces: map[uint64]*UnconfirmedTx{},
	}
}

func (s *TxStore) SetNextNonce(newNextNonce uint64) []*UnconfirmedTx {
	s.lock.Lock()
	defer s.lock.Unlock()

	staleTxs := []*UnconfirmedTx{}
	s.nextNonce = newNextNonce

	// Remove any stale transactions with nonces greater than the new next nonce.
	for nonce, tx := range s.unconfirmedNonces {
		if nonce >= s.nextNonce {
			staleTxs = append(staleTxs, tx)
			delete(s.unconfirmedNonces, nonce)
		}
	}

	sort.Slice(staleTxs, func(i, j int) bool {
		a := staleTxs[i]
		b := staleTxs[j]
		return a.Nonce < b.Nonce
	})

	return staleTxs
}

func (s *TxStore) GetNextNonce() uint64 {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.nextNonce
}

func (s *TxStore) AddUnconfirmed(nonce uint64, hash string, timestamp uint64, tx *AptosTx) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if nonce < s.nextNonce {
		return fmt.Errorf("tried to add an unconfirmed tx at an old nonce: expected %d, got %d", s.nextNonce, nonce)
	}
	if nonce > s.nextNonce {
		return fmt.Errorf("tried to add an unconfirmed tx at a future nonce: expected %d, got %d", s.nextNonce, nonce)
	}

	if h, exists := s.unconfirmedNonces[nonce]; exists {
		return fmt.Errorf("nonce used: tried to use nonce (%d) for tx (%s), already used by (%s)", nonce, hash, h.Hash)
	}

	s.unconfirmedNonces[nonce] = &UnconfirmedTx{
		Nonce:     nonce,
		Hash:      hash,
		Timestamp: timestamp,
		Tx:        tx,
	}

	s.nextNonce = s.nextNonce + 1
	return nil
}

func (s *TxStore) Confirm(nonce uint64, hash string) error {
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
	return nil
}

func (s *TxStore) GetUnconfirmed() []*UnconfirmedTx {
	s.lock.RLock()
	defer s.lock.RUnlock()

	unconfirmed := maps.Values(s.unconfirmedNonces)
	sort.Slice(unconfirmed, func(i, j int) bool {
		a := unconfirmed[i]
		b := unconfirmed[j]
		return a.Nonce < b.Nonce
	})

	return unconfirmed
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
	c.lock.Lock()
	defer c.lock.Unlock()
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
