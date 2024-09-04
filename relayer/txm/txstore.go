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
	uLock sync.RWMutex
	fLock sync.RWMutex

	nextNonce         uint64
	unconfirmedNonces map[uint64]*UnconfirmedTx
	failedNonces      map[uint64]struct{}
}

func NewTxStore(initialNonce uint64) *TxStore {
	return &TxStore{
		nextNonce:         initialNonce,
		unconfirmedNonces: make(map[uint64]*UnconfirmedTx),
		failedNonces:      make(map[uint64]struct{}),
	}
}

func (s *TxStore) SetNextNonce(newNextNonce uint64) []*UnconfirmedTx {
	s.uLock.Lock()
	defer s.uLock.Unlock()

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
	s.uLock.Lock()
	defer s.uLock.Unlock()
	return s.nextNonce
}

func (s *TxStore) AddUnconfirmed(nonce uint64, hash string, timestamp uint64, tx *AptosTx) error {
	s.uLock.Lock()
	defer s.uLock.Unlock()

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

func (s *TxStore) AddUnconfirmedRetry(nonce uint64, hash string, timestamp uint64, tx *AptosTx) error {
	s.uLock.Lock()
	defer s.uLock.Unlock()

	if h, exists := s.unconfirmedNonces[nonce]; exists {
		return fmt.Errorf("nonce used: tried to use nonce (%d) for tx (%s), already used by (%s)", nonce, hash, h.Hash)
	}

	s.unconfirmedNonces[nonce] = &UnconfirmedTx{
		Nonce:     nonce,
		Hash:      hash,
		Timestamp: timestamp,
		Tx:        tx,
	}

	return nil
}

func (s *TxStore) Confirm(nonce uint64, hash string) error {
	s.uLock.Lock()
	defer s.uLock.Unlock()

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
	s.uLock.RLock()
	defer s.uLock.RUnlock()

	unconfirmed := maps.Values(s.unconfirmedNonces)
	sort.Slice(unconfirmed, func(i, j int) bool {
		a := unconfirmed[i]
		b := unconfirmed[j]
		return a.Nonce < b.Nonce
	})

	return unconfirmed
}

func (s *TxStore) InflightCount() int {
	s.uLock.RLock()
	defer s.uLock.RUnlock()
	return len(s.unconfirmedNonces)
}

func (s *TxStore) AddFailedNonce(nonce uint64) {
	s.fLock.Lock()
	defer s.fLock.Unlock()

	s.failedNonces[nonce] = struct{}{}
}

func (s *TxStore) PopFailedNonce() (uint64, bool) {
	s.fLock.Lock()
	defer s.fLock.Unlock()

	if len(s.failedNonces) == 0 {
		return 0, false
	}

	// Convert the map keys to a slice and sort it
	var nonces []uint64
	for nonce := range s.failedNonces {
		nonces = append(nonces, nonce)
	}
	sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })

	smallestNonce := nonces[0]
	delete(s.failedNonces, smallestNonce)

	return smallestNonce, true
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
