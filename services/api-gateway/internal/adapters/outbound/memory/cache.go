package memory

import (
	"container/list"
	"sync"
	"time"

	"github.com/ocrosby/identity-platform-go/services/api-gateway/internal/ports"
)

// Compile-time check: Cache must satisfy ports.ResponseCache.
var _ ports.ResponseCache = (*Cache)(nil)

// Cache is a thread-safe LRU response cache with per-entry TTL expiry.
//
// Design: Proxy pattern — Cache implements ports.ResponseCache, standing between
// CacheMiddleware and the underlying map. LRU eviction keeps memory bounded without
// a background sweep goroutine: expired entries are removed eagerly on Get.
//
// Eviction order:
//  1. On Get: if the entry is past its expiry it is removed immediately and a miss
//     is returned, freeing memory without a separate goroutine.
//  2. On Set: when the map is at capacity the least-recently-used entry is evicted
//     to make room for the new one.
type Cache struct {
	mu    sync.Mutex
	max   int
	items map[string]*list.Element
	lru   *list.List
}

type cacheItem struct {
	key    string
	entry  *ports.CacheEntry
	expiry time.Time
}

// NewCache creates a Cache that holds at most maxEntries responses.
// maxEntries ≤ 0 defaults to 1000.
func NewCache(maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = 1000
	}
	return &Cache{
		max:   maxEntries,
		items: make(map[string]*list.Element, maxEntries),
		lru:   list.New(),
	}
}

// Get returns the cached entry and true on a cache hit.
// Returns nil and false on a miss or expired entry; stale entries are evicted immediately.
func (c *Cache) Get(key string) (*ports.CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	item := el.Value.(*cacheItem)
	if time.Now().After(item.expiry) {
		c.remove(el)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return item.entry, true
}

// Set stores entry under key with the given TTL.
// A zero or negative TTL is a no-op: the entry is not stored.
func (c *Cache) Set(key string, entry *ports.CacheEntry, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		c.lru.MoveToFront(el)
		item := el.Value.(*cacheItem)
		item.entry = entry
		item.expiry = time.Now().Add(ttl)
		return
	}
	if c.lru.Len() >= c.max {
		c.evictOldest()
	}
	item := &cacheItem{key: key, entry: entry, expiry: time.Now().Add(ttl)}
	el := c.lru.PushFront(item)
	c.items[key] = el
}

func (c *Cache) remove(el *list.Element) {
	item := el.Value.(*cacheItem)
	delete(c.items, item.key)
	c.lru.Remove(el)
}

func (c *Cache) evictOldest() {
	if el := c.lru.Back(); el != nil {
		c.remove(el)
	}
}
