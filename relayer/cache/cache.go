package cache

import (
	"sync"
	"time"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

type Entry[T any] struct {
	Value     T
	ExpiresAt time.Time
	Permanent bool
}

type Cache[K comparable, V any] struct {
	data       map[K]Entry[V]
	mu         sync.RWMutex
	defaultTTL time.Duration
	lggr       logger.Logger
}

func NewCache[K comparable, V any](defaultTTL time.Duration, lggr logger.Logger) *Cache[K, V] {
	return &Cache[K, V]{
		data:       make(map[K]Entry[V]),
		defaultTTL: defaultTTL,
		lggr:       logger.Named(lggr, "AptosCache"),
	}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	entry, exists := c.data[key]
	c.mu.RUnlock()

	if !exists {
		var zero V
		return zero, false
	}

	if !entry.Permanent && time.Now().After(entry.ExpiresAt) {
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()

		var zero V
		return zero, false
	}

	return entry.Value, true
}

func (c *Cache[K, V]) Set(key K, value V) {
	c.SetWithTTL(key, value, c.defaultTTL)
}

func (c *Cache[K, V]) SetWithTTL(key K, value V, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiresAt := time.Now().Add(ttl)
	c.data[key] = Entry[V]{
		Value:     value,
		ExpiresAt: expiresAt,
		Permanent: false,
	}
}

func (c *Cache[K, V]) SetPermanent(key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = Entry[V]{
		Value:     value,
		Permanent: true,
	}
}

func (c *Cache[K, V]) Delete(key K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

func (c *Cache[K, V]) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	count := 0

	for key, entry := range c.data {
		if !entry.Permanent && now.After(entry.ExpiresAt) {
			delete(c.data, key)
			count++
		}
	}

	return count
}

func (c *Cache[K, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}
