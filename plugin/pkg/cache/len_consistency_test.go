package cache

import (
	"math/rand"
	"testing"
)

// occupancy counts entries directly in the shard maps, independent of Len().
func occupancy[T any](c *Cache[T]) int {
	n := 0
	for _, s := range &c.shards {
		s.RLock()
		n += len(s.items)
		s.RUnlock()
	}
	return n
}

// TestCacheLenMatchesOccupancy drives inserts, overwrites, removals of present
// and absent keys, and random evictions (small shards, many keys), and checks
// after every operation that Len() equals the real occupancy. Any alternative
// Len implementation (e.g. a maintained counter) must keep this true.
func TestCacheLenMatchesOccupancy(t *testing.T) {
	for _, size := range []int{4, shardSize, shardSize * 4} {
		c := New[int](size)
		rng := rand.New(rand.NewSource(int64(size)))
		keySpace := uint64(size * 3) // > capacity so evictions happen
		for i := range 20000 {
			k := rng.Uint64() % keySpace
			switch rng.Intn(3) {
			case 0, 1:
				c.Add(k, i) // insert, overwrite, or insert+evict
			case 2:
				c.Remove(k) // present or absent
			}
			if got, want := c.Len(), occupancy(c); got != want {
				t.Fatalf("size=%d op=%d: Len()=%d, occupancy=%d", size, i, got, want)
			}
		}
		// Targeted cases.
		c.Add(1, 1)
		before := c.Len()
		c.Add(1, 2) // overwrite
		if c.Len() != before {
			t.Fatalf("overwrite changed Len: %d -> %d", before, c.Len())
		}
		c.Remove(1 << 40) // absent
		if c.Len() != occupancy(c) {
			t.Fatalf("remove of absent key desynchronized Len")
		}
	}
	// Eviction at the shard bound: shard 0 holds `ssize` entries; adding a new
	// key to the full shard evicts one and keeps the count flat.
	c := New[int](4) // ssize = 4 per shard
	for i := range 4 {
		c.Add(uint64(i)*shardSize, i) // all map to shard 0
	}
	if c.Len() != 4 {
		t.Fatalf("fill shard: Len=%d", c.Len())
	}
	if !c.Add(99*shardSize, 99) {
		t.Fatal("expected an eviction")
	}
	if c.Len() != 4 || occupancy(c) != 4 {
		t.Fatalf("after eviction Len=%d occupancy=%d, want 4", c.Len(), occupancy(c))
	}
}

// TestCacheLenAfterWalkDelete covers callers (such as plugin/dnssec) that delete
// entries directly from the map handed to the Walk callback.
func TestCacheLenAfterWalkDelete(t *testing.T) {
	c := New[int](shardSize * 4)
	for i := range 1000 {
		c.Add(uint64(i), i)
	}
	c.Walk(func(items map[uint64]int, key uint64) bool {
		if key%3 == 0 {
			delete(items, key)
		}
		return true
	})
	if got, want := c.Len(), occupancy(c); got != want {
		t.Fatalf("after Walk deletes: Len()=%d, occupancy=%d", got, want)
	}
	if c.Len() == 1000 {
		t.Fatal("Walk callback did not delete anything")
	}
}

// TestCacheLenAfterShardEvict covers Evict, which removes one element.
func TestCacheLenAfterShardEvict(t *testing.T) {
	c := New[int](shardSize * 4)
	for i := range 100 {
		c.Add(uint64(i), i)
	}
	for _, s := range &c.shards {
		s.Evict()
	}
	if got, want := c.Len(), occupancy(c); got != want {
		t.Fatalf("after Evict: Len()=%d, occupancy=%d", got, want)
	}
}
