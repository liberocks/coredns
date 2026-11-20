package cache

// A cache write updates the coredns_cache_entries gauge. These tests and
// benchmarks make sure that update stays independent of the lock state of the
// cache's 256 shards: it used to call Len() on both caches, which took a read
// lock on every shard of each. All benchmark data is constructed outside the
// timed region.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const benchName = "bench.example.org."

func benchQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// benchReply is a fixed, cacheable, matching synthetic response.
func benchReply(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.RecursionAvailable = true
	m.Answer = []dns.RR{
		test.A(q.Question[0].Name + " 300 IN A 192.0.2.1"),
		test.A(q.Question[0].Name + " 300 IN A 192.0.2.2"),
	}
	return m
}

func nxReply(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(q)
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{test.SOA("example.org. 300 IN SOA ns.example.org. h.example.org. 1 7200 3600 1209600 300")}
	return m
}

// TestFillDoesNotWaitOnUnrelatedShards checks that a single cache write is not
// coupled to the lock state of shards its own key does not map to, in either
// cache.
//
// Method: Cache.Walk invokes its callback while holding that shard's write lock
// (the cache plugin never calls Walk in production; it is used here only as a
// way to hold one shard lock). We hold the shard of an unrelated entry and fill
// a different key. The fill must complete, and so must a cache hit.
func TestFillDoesNotWaitOnUnrelatedShards(t *testing.T) {
	type holdTarget struct {
		name    string
		seedKey string // name of the seeded entry whose shard we hold
		walk    func(c *Cache, f func(map[uint64]*item, uint64) bool)
	}
	targets := []holdTarget{
		{"success-cache shard held", "seed-p.example.org.", func(c *Cache, f func(map[uint64]*item, uint64) bool) { c.pcache.Walk(f) }},
		{"denial-cache shard held", "seed-n.example.org.", func(c *Cache, f func(map[uint64]*item, uint64) bool) { c.ncache.Walk(f) }},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			c := New()
			// Seed one entry in each cache so each has an occupied shard to hold.
			seedP := benchQuery("seed-p.example.org.")
			seedN := benchQuery("seed-n.example.org.")
			newPrefetchResponseWriter("", seedP, false, false, c).WriteMsg(benchReply(seedP))
			newPrefetchResponseWriter("", seedN, false, false, c).WriteMsg(nxReply(seedN))

			// Pick a fill key whose shard differs from the seeds' shards.
			seedShardP := hash("seed-p.example.org.", dns.TypeA, dns.ClassINET, false, false) & 255
			seedShardN := hash("seed-n.example.org.", dns.TypeA, dns.ClassINET, false, false) & 255
			var fillName string
			for i := 0; ; i++ {
				n := fmt.Sprintf("fill-%d.example.org.", i)
				s := hash(n, dns.TypeA, dns.ClassINET, false, false) & 255
				if s != seedShardP && s != seedShardN {
					fillName = n
					break
				}
			}
			fillKey := hash(fillName, dns.TypeA, dns.ClassINET, false, false)

			// Control: with nothing held, the fill returns promptly.
			ctl := benchQuery("control.example.org.")
			done := make(chan struct{})
			go func() {
				newPrefetchResponseWriter("", ctl, false, false, c).WriteMsg(benchReply(ctl))
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("control fill did not complete with no locks held")
			}

			// Hold the shard of the seed entry: Walk calls f under that shard's
			// write lock. Other shards are walked and released immediately.
			heldKey := hash(tc.seedKey, dns.TypeA, dns.ClassINET, false, false)
			hold, entered := make(chan struct{}), make(chan struct{})
			go tc.walk(c, func(_ map[uint64]*item, k uint64) bool {
				if k == heldKey {
					close(entered)
					<-hold
				}
				return true
			})
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("could not take the shard lock")
			}
			released := false
			release := func() {
				if !released {
					released = true
					close(hold)
				}
			}
			defer release()

			// Fill an unrelated key while one shard is write-locked.
			q := benchQuery(fillName)
			filled := make(chan struct{})
			go func() {
				newPrefetchResponseWriter("", q, false, false, c).WriteMsg(benchReply(q))
				close(filled)
			}()

			// The fill must complete while the unrelated shard is still held.
			select {
			case <-filled:
			case <-time.After(5 * time.Second):
				t.Fatal("WriteMsg blocked on an unrelated shard lock")
			}
			if _, ok := c.pcache.Get(fillKey); !ok {
				t.Fatal("fill did not store the entry")
			}

			// A hit on the stored entry only touches its own shard.
			ctx := context.Background()
			c.Next = plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
				t.Error("hit reached the next plugin")
				return dns.RcodeServerFailure, nil
			})
			hit := make(chan struct{})
			go func() {
				c.ServeDNS(ctx, dnstest.NewRecorder(&test.ResponseWriter{}), benchQuery(fillName))
				close(hit)
			}()
			select {
			case <-hit:
			case <-time.After(5 * time.Second):
				t.Fatal("cache hit was blocked by an unrelated shard lock")
			}

			release()
		})
	}
}

// TestFillGaugeMatchesOccupancy records the behavior any replacement of the
// per-fill Len() must preserve: the entries gauge equals actual occupancy
// after inserts, overwrites, denial writes, and the removal of a denial when a
// positive refresh replaces it.
func TestFillGaugeMatchesOccupancy(t *testing.T) {
	c := New()
	check := func(step string) {
		t.Helper()
		g := func(typ string) int {
			return int(testutil.ToFloat64(cacheSize.WithLabelValues("gauge", typ, c.zonesMetricLabel, c.viewMetricLabel)))
		}
		if gp, np := g(Success), c.pcache.Len(); gp != np {
			t.Fatalf("%s: success gauge %d != occupancy %d", step, gp, np)
		}
		if gn, nn := g(Denial), c.ncache.Len(); gn != nn {
			t.Fatalf("%s: denial gauge %d != occupancy %d", step, gn, nn)
		}
	}
	w := func(name string, nx bool) {
		q := benchQuery(name)
		cw := newPrefetchResponseWriter("gauge", q, false, false, c)
		r := benchReply(q)
		if nx {
			r = nxReply(q)
		}
		cw.WriteMsg(r)
	}
	w("a.example.org.", false)
	check("insert a")
	w("a.example.org.", false)
	check("overwrite a")
	w("b.example.org.", true)
	check("denial b")
	w("b.example.org.", false) // prefetch refresh turns the denial into a positive entry, removing it from ncache
	check("positive replaces denial b")
	if c.ncache.Len() != 0 || c.pcache.Len() != 2 {
		t.Fatalf("unexpected occupancy p=%d n=%d", c.pcache.Len(), c.ncache.Len())
	}
}

// ---- Benchmarks -------------------------------------------------------------

// BenchmarkCacheLenOnly isolates the gauge update: pcache.Len() + ncache.Len().
func BenchmarkCacheLenOnly(b *testing.B) {
	c := New()
	b.ReportAllocs()
	var sink int
	for b.Loop() {
		sink += c.pcache.Len() + c.ncache.Len()
	}
	_ = sink
}

// BenchmarkCacheFill measures ResponseWriter.WriteMsg for one fixed, matching,
// cacheable response on a normal (non-prefetch) writer: the fill path with a
// no-op client write.
func BenchmarkCacheFill(b *testing.B) {
	for _, occ := range []int{1, 100000} {
		b.Run(fmt.Sprintf("entries=%d", occ), func(b *testing.B) {
			c := New()
			populate(c, occ)
			q := benchQuery(benchName)
			res := benchReply(q)
			cw := fillWriter(c, q)
			b.ReportAllocs()
			for b.Loop() {
				cw.WriteMsg(res)
			}
		})
	}
}

// BenchmarkCacheFillParallel is the same fill under GOMAXPROCS concurrent
// writers (each with its own writer and its own key).
func BenchmarkCacheFillParallel(b *testing.B) {
	c := New()
	var id atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		q := benchQuery(fmt.Sprintf("par-%d.example.org.", id.Add(1)))
		res := benchReply(q)
		cw := fillWriter(c, q)
		for pb.Next() {
			cw.WriteMsg(res)
		}
	})
}

// BenchmarkCacheHit is the warm-hit control: the same cache, no fill.
func BenchmarkCacheHit(b *testing.B) {
	c := New()
	q := benchQuery(benchName)
	newPrefetchResponseWriter("", q, false, false, c).WriteMsg(benchReply(q))
	c.Next = plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		b.Fatal("hit reached next plugin")
		return 0, nil
	})
	ctx := context.Background()
	w := &test.ResponseWriter{}
	b.ReportAllocs()
	for b.Loop() {
		c.ServeDNS(ctx, w, q)
	}
}

// BenchmarkCacheHitParallel is the parallel hit control.
func BenchmarkCacheHitParallel(b *testing.B) {
	c := New()
	q := benchQuery(benchName)
	newPrefetchResponseWriter("", q, false, false, c).WriteMsg(benchReply(q))
	c.Next = plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		b.Error("hit reached next plugin")
		return 0, nil
	})
	ctx := context.Background()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		w := &test.ResponseWriter{}
		for pb.Next() {
			c.ServeDNS(ctx, w, q)
		}
	})
}

// BenchmarkCacheMissAndFill is the full ServeDNS miss path (lookup, next
// plugin, WriteMsg fill, client write) for a fake next that answers
// immediately. The clock advances two hours per call so each request finds an
// expired entry and therefore misses, like an expiry wave.
func BenchmarkCacheMissAndFill(b *testing.B) {
	c := New()
	c.now = expiringClock()
	q := benchQuery(benchName)
	res := benchReply(q)
	var nextCalls atomic.Int64
	c.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalls.Add(1)
		w.WriteMsg(res)
		return dns.RcodeSuccess, nil
	})
	ctx := context.Background()
	w := &test.ResponseWriter{}
	b.ReportAllocs()
	n := 0
	for b.Loop() {
		c.ServeDNS(ctx, w, q)
		n++
	}
	// Guard: every iteration must really have been a miss that was filled.
	if got := int(nextCalls.Load()); got != n {
		b.Fatalf("benchmark is not measuring misses: %d iterations, %d next-plugin calls", n, got)
	}
}

// BenchmarkCacheMissAndFillParallel is the parallel version of the above, over
// 64 preconstructed keys so that writers spread across shards.
func BenchmarkCacheMissAndFillParallel(b *testing.B) {
	const keys = 64
	c := New()
	c.now = expiringClock()
	queries := make([]*dns.Msg, keys)
	replies := make(map[string]*dns.Msg, keys)
	for i := range keys {
		queries[i] = benchQuery(fmt.Sprintf("mpar-%d.example.org.", i))
		replies[queries[i].Question[0].Name] = benchReply(queries[i])
	}
	var nextCalls, served atomic.Int64
	c.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalls.Add(1)
		w.WriteMsg(replies[r.Question[0].Name])
		return dns.RcodeSuccess, nil
	})
	ctx := context.Background()
	var id atomic.Int64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		q := queries[int(id.Add(1))%keys]
		w := &test.ResponseWriter{}
		for pb.Next() {
			c.ServeDNS(ctx, w, q)
			served.Add(1)
		}
	})
	// Guard: every request must have missed and been filled.
	if n, s := nextCalls.Load(), served.Load(); n != s {
		b.Fatalf("benchmark is not measuring only misses: %d requests, %d next-plugin calls", s, n)
	}
}

// expiringClock returns a clock that advances two hours on every call, so any
// entry stored at one call is expired at the next (default max TTL is one hour).
// It is built from Unix seconds: adding tick*time.Hour as a time.Duration
// overflows int64 after ~2.5M hours, which silently turns misses into hits in
// long benchmark runs.
func expiringClock() func() time.Time {
	var tick atomic.Int64
	const base = 1_700_000_000
	return func() time.Time { return time.Unix(base+tick.Add(1)*7200, 0) }
}

// fillWriter is the writer a normal (non-prefetch) miss fill uses: the response
// is cached and then written to the client writer (a no-op test writer).
func fillWriter(c *Cache, q *dns.Msg) *ResponseWriter {
	w := &test.ResponseWriter{}
	return &ResponseWriter{ResponseWriter: w, Cache: c, state: request.Request{W: w, Req: q}}
}

func populate(c *Cache, n int) {
	for i := range n {
		q := benchQuery(fmt.Sprintf("pop-%d.example.org.", i))
		c.pcache.Add(hash(q.Question[0].Name, dns.TypeA, dns.ClassINET, false, false), newItem(benchReply(q), time.Now(), time.Hour))
	}
}
