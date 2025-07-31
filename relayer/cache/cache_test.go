package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/smartcontractkit/chainlink-common/pkg/logger"
)

func TestCache(t *testing.T) {
	lggr := logger.Test(t)

	t.Run("Basic set and get", func(t *testing.T) {
		cache := NewCache[string, int](5*time.Minute, lggr)

		cache.Set("test", 123)

		value, exists := cache.Get("test")
		assert.True(t, exists)
		assert.Equal(t, 123, value)

		value, exists = cache.Get("nonexistent")
		assert.False(t, exists)
		assert.Equal(t, 0, value)
	})

	t.Run("Expiration", func(t *testing.T) {
		cache := NewCache[string, string](10*time.Millisecond, lggr)
		cache.Set("shortlived", "value")

		value, exists := cache.Get("shortlived")
		assert.True(t, exists)
		assert.Equal(t, "value", value)

		time.Sleep(20 * time.Millisecond)

		value, exists = cache.Get("shortlived")
		assert.False(t, exists)
		assert.Equal(t, "", value)
	})

	t.Run("Custom TTL", func(t *testing.T) {
		cache := NewCache[string, string](5*time.Minute, lggr)

		cache.SetWithTTL("custom", "value", 10*time.Millisecond)

		time.Sleep(20 * time.Millisecond)

		_, exists := cache.Get("custom")
		assert.False(t, exists)
	})

	t.Run("Permanent entry", func(t *testing.T) {
		cache := NewCache[string, string](10*time.Millisecond, lggr)

		cache.SetPermanent("permanent", "forever")

		cache.Set("temporary", "gone soon")

		time.Sleep(20 * time.Millisecond)

		val, exists := cache.Get("permanent")
		assert.True(t, exists)
		assert.Equal(t, "forever", val)

		_, exists = cache.Get("temporary")
		assert.False(t, exists)
	})

	t.Run("Purge", func(t *testing.T) {
		cache := NewCache[string, string](10*time.Millisecond, lggr)

		cache.Set("a", "1")
		cache.Set("b", "2")
		cache.Set("c", "3")
		cache.SetPermanent("d", "4")

		time.Sleep(20 * time.Millisecond)

		count := cache.Purge()
		assert.Equal(t, 3, count)

		assert.Equal(t, 1, cache.Size())
		val, exists := cache.Get("d")
		assert.True(t, exists)
		assert.Equal(t, "4", val)
	})

	t.Run("Delete", func(t *testing.T) {
		cache := NewCache[string, string](5*time.Minute, lggr)

		cache.Set("key", "value")
		cache.SetPermanent("permanent", "value")

		cache.Delete("key")
		cache.Delete("permanent")

		_, exists := cache.Get("key")
		assert.False(t, exists)

		_, exists = cache.Get("permanent")
		assert.False(t, exists)
	})
}
