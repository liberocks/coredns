// Package cache implements a cache. The cache hold 256 shards, each shard
// holds a cache: a map with a mutex. There is no fancy expunge algorithm, it
// just randomly evicts elements when it gets full.
package cache

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
)

// Hash returns the FNV hash of what.
func Hash(what []byte) uint64 {
	h := fnv.New64()
	h.Write(what)
	return h.Sum64()
}

// Cache is cache.
type Cache[T any] struct {
	shards [shardSize]*shard[T]

	// total is the number of elements across all shards. Each shard updates it
	// while holding its own lock, so Len does not need to lock every shard.
	total atomic.Int64
}

// shard is a cache with random eviction.
type shard[T any] struct {
	items map[uint64]T
	size  int

	// total is the owning Cache's element counter. It is nil for a standalone shard.
	total *atomic.Int64

	sync.RWMutex
}

// New returns a new cache.
func New[T any](size int) *Cache[T] {
	ssize := max(size/shardSize, 4)

	c := &Cache[T]{}

	// Initialize all the shards
	for i := range shardSize {
		c.shards[i] = newShard[T](ssize)
		c.shards[i].total = &c.total
	}
	return c
}

// Add adds a new element to the cache. If the element already exists it is overwritten.
// Returns true if an existing element was evicted to make room for this element.
func (c *Cache[T]) Add(key uint64, el T) bool {
	shard := key & (shardSize - 1)
	return c.shards[shard].Add(key, el)
}

// Get looks up element index under key.
func (c *Cache[T]) Get(key uint64) (T, bool) {
	shard := key & (shardSize - 1)
	return c.shards[shard].Get(key)
}

// Remove removes the element indexed with key.
func (c *Cache[T]) Remove(key uint64) {
	shard := key & (shardSize - 1)
	c.shards[shard].Remove(key)
}

// Len returns the number of elements in the cache. It reads a maintained
// counter and takes no shard locks, so it is cheap enough to call on hot paths.
func (c *Cache[T]) Len() int {
	return int(c.total.Load())
}

// Walk walks each shard in the cache.
func (c *Cache[T]) Walk(f func(map[uint64]T, uint64) bool) {
	for _, s := range &c.shards {
		s.Walk(f)
	}
}

// newShard returns a new shard with size.
func newShard[T any](size int) *shard[T] { return &shard[T]{items: make(map[uint64]T), size: size} }

// Add adds element indexed by key into the cache. Any existing element is overwritten
// Returns true if an existing element was evicted to make room for this element.
func (s *shard[T]) Add(key uint64, el T) bool {
	eviction := false
	s.Lock()
	before := len(s.items)
	if len(s.items) >= s.size {
		if _, ok := s.items[key]; !ok {
			for k := range s.items {
				delete(s.items, k)
				eviction = true
				break
			}
		}
	}
	s.items[key] = el
	s.count(len(s.items) - before)
	s.Unlock()
	return eviction
}

// Remove removes the element indexed by key from the cache.
func (s *shard[T]) Remove(key uint64) {
	s.Lock()
	before := len(s.items)
	delete(s.items, key)
	s.count(len(s.items) - before)
	s.Unlock()
}

// Evict removes a random element from the cache.
func (s *shard[T]) Evict() {
	s.Lock()
	for k := range s.items {
		delete(s.items, k)
		s.count(-1)
		break
	}
	s.Unlock()
}

// count adds delta to the owning cache's element counter. The caller holds the
// shard's write lock.
func (s *shard[T]) count(delta int) {
	if s.total != nil && delta != 0 {
		s.total.Add(int64(delta))
	}
}

// Get looks up the element indexed under key.
func (s *shard[T]) Get(key uint64) (T, bool) {
	s.RLock()
	el, found := s.items[key]
	s.RUnlock()
	return el, found
}

// Len returns the current length of the cache.
func (s *shard[T]) Len() int {
	s.RLock()
	l := len(s.items)
	s.RUnlock()
	return l
}

// Walk walks the shard for each element the function f is executed while holding a write lock.
// f may delete elements from the map it is given; the cache's element count follows.
func (s *shard[T]) Walk(f func(map[uint64]T, uint64) bool) {
	s.RLock()
	items := make([]uint64, len(s.items))
	i := 0
	for k := range s.items {
		items[i] = k
		i++
	}
	s.RUnlock()
	for _, k := range items {
		s.Lock()
		before := len(s.items)
		ok := f(s.items, k)
		s.count(len(s.items) - before)
		s.Unlock()
		if !ok {
			return
		}
	}
}

const shardSize = 256
