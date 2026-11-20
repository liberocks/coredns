package cache

// Overlapping cache misses for the same key.
//
// These tests characterize the current behavior: the cache has no in-flight
// (single-flight) tracking for misses, so every request that finds no usable
// entry calls the next plugin immediately. They are written so that a
// coalescing implementation would still terminate (bounded waits, no
// unconditional rendezvous in the fake handler) and fail with a clear message
// rather than hang.
//
// How "the second request reached the miss path" is observed without touching
// production code: getIfNotStale increments coredns_cache_misses_total for the
// request's server label. Each test uses its own server label (via the
// dnsserver.Key context value), so the counter is private to the test.

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	missWait   = 5 * time.Second        // upper bound for a request to reach the miss path
	missSettle = 500 * time.Millisecond // how long we wait for a downstream call that never comes (coalesced case)
)

// blockingResolver is a fake next plugin. Every call is counted, announced on
// entered, and then held until release is closed.
type blockingResolver struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	delay   time.Duration // optional fixed latency instead of blocking on release
}

func newBlockingResolver(n int) *blockingResolver {
	return &blockingResolver{entered: make(chan struct{}, n*4), release: make(chan struct{})}
}

func (b *blockingResolver) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	b.calls.Add(1)
	b.entered <- struct{}{}
	if b.delay > 0 {
		time.Sleep(b.delay)
	} else {
		<-b.release
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response = true
	// Echo the query's DO/CD so a response always matches its own request key.
	m.CheckingDisabled = r.CheckingDisabled
	// Answer with a record of the queried type; a non-answer without SOA is
	// (correctly) not cached and would hide the effect under test.
	if r.Question[0].Qtype == dns.TypeAAAA {
		m.Answer = []dns.RR{test.AAAA(r.Question[0].Name + " 300 IN AAAA ::1")}
	} else {
		m.Answer = []dns.RR{test.A(r.Question[0].Name + " 300 IN A 127.0.0.1")}
	}
	if o := r.IsEdns0(); o != nil {
		m.SetEdns0(o.UDPSize(), o.Do())
	}
	if err := w.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, nil
}

func (b *blockingResolver) Name() string { return "blockingResolver" }

type missReq struct {
	name  string
	qtype uint16
	do    bool
	cd    bool
	id    uint16
}

func (q missReq) msg() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(q.name, q.qtype)
	m.CheckingDisabled = q.cd
	if q.do {
		m.SetEdns0(4096, true)
	}
	if q.id != 0 {
		m.Id = q.id
	}
	return m
}

var serverSeq atomic.Int64

// missServer returns a context carrying a server label unique to this test, and
// a function reading how many cache misses were recorded under that label.
func missServer(t *testing.T, c *Cache) (context.Context, func() int, func() int) {
	t.Helper()
	// Unique per call: with -count>1 the same t.Name() would otherwise reuse a
	// counter that already holds the previous iteration's misses.
	addr := fmt.Sprintf("miss-overlap-%s-%d", t.Name(), serverSeq.Add(1))
	ctx := context.WithValue(context.Background(), dnsserver.Key{}, &dnsserver.Server{Addr: addr})
	misses := func() int {
		return int(testutil.ToFloat64(cacheMisses.WithLabelValues(addr, c.zonesMetricLabel, c.viewMetricLabel)))
	}
	hits := func() int {
		return int(testutil.ToFloat64(cacheHits.WithLabelValues(addr, Success, c.zonesMetricLabel, c.viewMetricLabel)))
	}
	return ctx, misses, hits
}

func waitFor(cond func() bool, bound time.Duration) bool {
	deadline := time.Now().Add(bound)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// runOverlap starts one goroutine per request on a cold cache, holds the fake
// resolver, waits until every request has reached the miss path, and reports
// the downstream call count observed before anything was released. It then
// releases, validates every response and issues a serial request for the first
// key to check it is served from cache.
func runOverlap(t *testing.T, reqs []missReq) (callsBeforeRelease, entries int) {
	t.Helper()
	c := New()
	b := newBlockingResolver(len(reqs))
	c.Next = b
	ctx, misses, hits := missServer(t, c)

	type result struct {
		rec *dnstest.Recorder
		rc  int
		err error
	}
	results := make([]result, len(reqs))
	var wg sync.WaitGroup
	for i, q := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			rc, err := c.ServeDNS(ctx, rec, q.msg())
			results[i] = result{rec, rc, err}
		}()
	}

	// Every request must have reached the miss path before we look at the
	// downstream count; otherwise a count of 1 could just mean "second request
	// is still on its way".
	if !waitFor(func() bool { return misses() == len(reqs) }, missWait) {
		close(b.release)
		wg.Wait()
		t.Fatalf("only %d of %d requests reached the cache miss path within %s", misses(), len(reqs), missWait)
	}
	// Give downstream calls a bounded moment to appear. In the current
	// implementation they are immediate; a coalescing implementation would
	// never reach len(reqs) and simply times out here.
	waitFor(func() bool { return int(b.calls.Load()) == len(reqs) }, missSettle)
	callsBeforeRelease = int(b.calls.Load())

	close(b.release)
	wg.Wait()

	for i, r := range results {
		if r.err != nil || r.rc != dns.RcodeSuccess {
			t.Fatalf("request %d: rcode=%d err=%v", i, r.rc, r.err)
		}
		if r.rec.Msg == nil || r.rec.Msg.Rcode != dns.RcodeSuccess || len(r.rec.Msg.Answer) != 1 {
			t.Fatalf("request %d: invalid response %v", i, r.rec.Msg)
		}
		if rr := r.rec.Msg.Answer[0]; rr.Header().Rrtype != reqs[i].qtype {
			t.Fatalf("request %d: answer type %d, want %d", i, rr.Header().Rrtype, reqs[i].qtype)
		}
	}

	// Serial follow-up: must be a warm hit and must not call downstream again.
	callsAfterOverlap := int(b.calls.Load())
	hitsBefore := hits()
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := c.ServeDNS(ctx, rec, reqs[0].msg()); err != nil {
		t.Fatalf("serial follow-up: %v", err)
	}
	if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
		t.Fatalf("serial follow-up: invalid response %v", rec.Msg)
	}
	if got := int(b.calls.Load()); got != callsAfterOverlap {
		t.Fatalf("serial follow-up reached the resolver: calls %d -> %d, want a warm hit", callsAfterOverlap, got)
	}
	if got := hits(); got != hitsBefore+1 {
		t.Fatalf("serial follow-up was not counted as a cache hit: hits %d -> %d", hitsBefore, got)
	}
	// Occupancy after the burst: redundant calls collapse into one entry per key.
	return callsBeforeRelease, c.pcache.Len()
}

// TestOverlappingMissesSameKey is the core reproduction: N overlapping requests
// for an identical key on an empty cache reach the resolver N times.
func TestOverlappingMissesSameKey(t *testing.T) {
	q := missReq{name: "overlap.example.org.", qtype: dns.TypeA}
	for _, n := range []int{2, 8, 64} {
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			reqs := make([]missReq, n)
			for i := range reqs {
				reqs[i] = q
				reqs[i].id = uint16(1000 + i) // each request has its own message ID
			}
			got, entries := runOverlap(t, reqs)
			t.Logf("same key, %d overlapping misses -> %d downstream calls before any answer was stored, %d cache entry", n, got, entries)
			if entries != 1 {
				t.Fatalf("want 1 cache entry for a single key, got %d", entries)
			}
			if got != n {
				t.Fatalf("want %d downstream calls (no coalescing in the baseline), got %d. "+
					"If this is a coalescing change, update this test; otherwise the suspicion is not reproduced.", n, got)
			}
		})
	}
}

// TestOverlappingMissesKeyIdentity shows which request differences still map to
// the SAME cache key (so duplication applies) and which map to distinct keys
// (where one call per key is correct).
func TestOverlappingMissesKeyIdentity(t *testing.T) {
	base := missReq{name: "keyid.example.org.", qtype: dns.TypeA}
	cases := []struct {
		name        string
		a, b        missReq
		wantCalls   int
		wantEntries int // 1: the second call was redundant; 2: both calls were necessary
	}{
		{"same key / different message ID", base, missReq{name: base.name, qtype: dns.TypeA, id: 4242}, 2, 1},
		{"same key / different qname case", base, missReq{name: "KeyID.Example.ORG.", qtype: dns.TypeA}, 2, 1},
		{"distinct key / different name", base, missReq{name: "other.example.org.", qtype: dns.TypeA}, 2, 2},
		{"distinct key / different qtype", base, missReq{name: base.name, qtype: dns.TypeAAAA}, 2, 2},
		{"distinct key / DO bit", base, missReq{name: base.name, qtype: dns.TypeA, do: true}, 2, 2},
		{"distinct key / CD bit", base, missReq{name: base.name, qtype: dns.TypeA, cd: true}, 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := tc.a, tc.b
			if a.id == 0 {
				a.id = 1
			}
			if b.id == 0 {
				b.id = 2
			}
			got, entries := runOverlap(t, []missReq{a, b})
			t.Logf("%s -> %d downstream calls, %d cache entry(ies)", tc.name, got, entries)
			if got != tc.wantCalls {
				t.Fatalf("want %d downstream calls, got %d", tc.wantCalls, got)
			}
			if entries != tc.wantEntries {
				t.Fatalf("want %d cache entries, got %d", tc.wantEntries, entries)
			}
		})
	}
}

// TestDistinctKeysAreIndependent distinguishes duplication from legitimate
// per-key work: after an overlapping burst on key A, key B is a separate miss
// (1 more call) and key A stays warm (0 more calls).
func TestDistinctKeysAreIndependent(t *testing.T) {
	c := New()
	b := newBlockingResolver(4)
	close(b.release) // no holding needed for this serial check
	c.Next = b
	ctx, _, _ := missServer(t, c)

	serve := func(name string) {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		if _, err := c.ServeDNS(ctx, rec, (&missReq{name: name, qtype: dns.TypeA}).msg()); err != nil {
			t.Fatal(err)
		}
	}
	serve("a.example.org.")
	serve("a.example.org.")
	if got := b.calls.Load(); got != 1 {
		t.Fatalf("serial same key: want 1 call, got %d", got)
	}
	serve("b.example.org.")
	if got := b.calls.Load(); got != 2 {
		t.Fatalf("second distinct key: want 2 calls total, got %d", got)
	}
}

// TestOverlappingMissesStaggered models the realistic shape: requests for one
// key arrive at a steady rate while the resolver takes `latency` to answer.
// Every request arriving before the first answer is stored misses, so the
// downstream calls are roughly rate x latency instead of 1.
func TestOverlappingMissesStaggered(t *testing.T) {
	const (
		total    = 200
		interval = time.Millisecond
		latency  = 50 * time.Millisecond
	)
	c := New()
	b := newBlockingResolver(total)
	b.delay = latency
	c.Next = b
	ctx, _, _ := missServer(t, c)

	var wg sync.WaitGroup
	for i := range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := dnstest.NewRecorder(&test.ResponseWriter{})
			c.ServeDNS(ctx, rec, (&missReq{name: "stagger.example.org.", qtype: dns.TypeA, id: uint16(i + 1)}).msg())
		}()
		time.Sleep(interval)
	}
	wg.Wait()
	got := int(b.calls.Load())
	t.Logf("%d requests, 1 per %s, resolver latency %s -> %d downstream calls (1 would be ideal; expected ~ latency/interval = %d)",
		total, interval, latency, got, int(latency/interval))
	if got < 2 {
		t.Fatalf("expected duplicate downstream calls during the miss window, got %d", got)
	}
	if got >= total {
		t.Fatalf("expected the cache to absorb later requests, got %d calls for %d requests", got, total)
	}
}

// TestMissPathHasNoInFlightGuard documents why a miss is unguarded: the only
// in-flight guard in the package is a CAS on an existing *item* (beginRefresh),
// used by prefetch and serve_stale refreshes. A miss has no item yet, so there
// is nothing to guard on. TestPrefetchDedup is the behavioral control for the
// guarded path.
func TestMissPathHasNoInFlightGuard(t *testing.T) {
	var i item
	if !i.beginRefresh(time.Now(), 0) {
		t.Fatal("first beginRefresh on an item should win")
	}
	if i.beginRefresh(time.Now(), 0) {
		t.Fatal("second beginRefresh on the same item should be rejected")
	}
}
