package cache

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// These tests check the contract of the `disable success|denial ZONES` option:
// a response in a disabled category must never be stored for a name in ZONES,
// regardless of which code path writes the response (ordinary miss, prefetch,
// serve_stale immediate refresh, serve_stale verify, verify with a timeout).
//
// Every case uses a real Corefile parsed by cacheParse, a controlled clock,
// an in-process next handler, and completion signals for background refreshes,
// so a failure reflects an unexpected cache insertion and not goroutine timing.

const (
	exclZone = "excluded.example.org."
	exclName = "svc.excluded.example.org." // inside the excluded zone
	ctrlName = "svc.included.example.org." // cached by the same stanza, outside the excluded zone
)

const (
	respPositive int32 = iota // A record, TTL 100
	respNXDomain              // NXDOMAIN with SOA, TTL 100
)

// refreshEnv wires a parsed Cache to a controllable clock and a fake next handler.
type refreshEnv struct {
	t       *testing.T
	c       *Cache
	base    time.Time
	offset  atomic.Int64
	mode    atomic.Int32 // what the fake upstream answers: respPositive or respNXDomain
	calls   atomic.Int32 // number of times the fake upstream was called
	gate    atomic.Pointer[chan struct{}]
	written chan struct{} // one token per response written by the fake upstream
}

func newRefreshEnv(t *testing.T, disable, extra string) *refreshEnv {
	t.Helper()
	// The zone argument is explicit because a test controller has no server block keys.
	corefile := fmt.Sprintf("cache . {\n\tdisable %s %s\n%s\n}", disable, exclZone, extra)
	ca, err := cacheParse(caddy.NewTestController("dns", corefile))
	if err != nil {
		t.Fatalf("cacheParse(%q): %v", corefile, err)
	}
	e := &refreshEnv{
		t:       t,
		c:       ca,
		base:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		written: make(chan struct{}, 64),
	}
	ca.now = func() time.Time { return e.base.Add(time.Duration(e.offset.Load())) }
	ca.Next = e
	return e
}

func (e *refreshEnv) setNow(d time.Duration) { e.offset.Store(int64(d)) }

// Name and ServeDNS make refreshEnv a plugin.Handler acting as the upstream.
func (e *refreshEnv) Name() string { return "fake-upstream" }

func (e *refreshEnv) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	e.calls.Add(1)
	if g := e.gate.Load(); g != nil {
		select {
		case <-*g:
		case <-ctx.Done():
			return dns.RcodeServerFailure, ctx.Err()
		}
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Response, m.RecursionAvailable = true, true
	rcode := dns.RcodeSuccess
	if e.mode.Load() == respNXDomain {
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{test.SOA("example.org. 100 IN SOA sns.dns.icann.org. noc.dns.icann.org. 2016082540 7200 3600 1209600 3600")}
		rcode = dns.RcodeNameError
	} else {
		m.Answer = []dns.RR{test.A(fmt.Sprintf("%s 100 IN A 127.0.0.53", r.Question[0].Name))}
	}
	w.WriteMsg(m) // cache insertion happens synchronously inside this call
	select {
	case e.written <- struct{}{}:
	default:
	}
	return rcode, nil
}

func (e *refreshEnv) query(name string) *dns.Msg {
	e.t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := e.c.ServeDNS(context.Background(), rec, req); err != nil {
		e.t.Fatalf("ServeDNS(%s): %v", name, err)
	}
	if rec.Msg == nil {
		e.t.Fatalf("ServeDNS(%s): no response written", name)
	}
	return rec.Msg
}

func (e *refreshEnv) key(name string) uint64 {
	return hash(name, dns.TypeA, dns.ClassINET, false, false)
}

func (e *refreshEnv) pItem(name string) (*item, bool) { return e.c.pcache.Get(e.key(name)) }
func (e *refreshEnv) nItem(name string) (*item, bool) { return e.c.ncache.Get(e.key(name)) }

func (e *refreshEnv) inP(name string) bool { _, ok := e.pItem(name); return ok }
func (e *refreshEnv) inN(name string) bool { _, ok := e.nItem(name); return ok }

func (e *refreshEnv) drain() {
	for {
		select {
		case <-e.written:
		default:
			return
		}
	}
}

// waitWritten blocks until the fake upstream has written one response (i.e. the
// refresh has passed through the cache ResponseWriter) and the refresh goroutine
// guarding seed has finished.
func (e *refreshEnv) waitWritten(seed *item) {
	e.t.Helper()
	select {
	case <-e.written:
	case <-time.After(5 * time.Second):
		e.t.Fatal("background refresh never reached the upstream")
	}
	e.settle(seed)
}

func (e *refreshEnv) settle(seed *item) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for seed.refreshing.Load() {
		if time.Now().After(deadline) {
			e.t.Fatal("background refresh never finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func rcodeName(m *dns.Msg) string { return dns.RcodeToString[m.Rcode] }

// refreshPath describes one way a cached entry gets refreshed.
type refreshPath struct {
	name      string
	extra     string        // extra cache directives
	refreshAt time.Duration // clock offset at which the refresh is driven
	// trigger drives the refresh and returns once the cache has processed the
	// refreshed response. It returns the response seen by the triggering client.
	trigger func(e *refreshEnv, name string, seed *item) *dns.Msg
}

// viaBackground triggers a refresh that runs in a goroutine after the client
// has already been answered from the cache (prefetch, serve_stale immediate).
func viaBackground(e *refreshEnv, name string, seed *item) *dns.Msg {
	wire := e.query(name)
	e.waitWritten(seed)
	return wire
}

// viaForeground triggers a refresh that is awaited by the request itself.
func viaForeground(e *refreshEnv, name string, _ *item) *dns.Msg {
	wire := e.query(name)
	e.drain()
	return wire
}

// viaSlowVerify forces the verify timeout to elapse before the upstream
// answers: the client gets the stale entry, then the background verify
// finishes and updates the cache.
func viaSlowVerify(e *refreshEnv, name string, seed *item) *dns.Msg {
	gate := make(chan struct{})
	e.gate.Store(&gate)
	wire := e.query(name) // returns once the 50ms verify timeout fires
	close(gate)
	e.waitWritten(seed)
	e.gate.Store(nil)
	return wire
}

var refreshPaths = []refreshPath{
	{
		name:      "prefetch",
		extra:     "\tprefetch 1 1m 50%",
		refreshAt: 60 * time.Second, // TTL 100: 40s left, inside the 50% window
		trigger:   viaBackground,
	},
	{
		name:      "serve_stale/immediate",
		extra:     "\tserve_stale 1h immediate",
		refreshAt: 150 * time.Second, // expired, inside the stale window
		trigger:   viaBackground,
	},
	{
		name:      "serve_stale/verify",
		extra:     "\tserve_stale 1h verify",
		refreshAt: 150 * time.Second,
		trigger:   viaForeground,
	},
	{
		name:      "serve_stale/verify+timeout(fast upstream)",
		extra:     "\tserve_stale 1h verify 5s",
		refreshAt: 150 * time.Second,
		trigger:   viaForeground,
	},
	{
		name:      "serve_stale/verify+timeout(slow upstream, bg completes)",
		extra:     "\tserve_stale 1h verify 50ms",
		refreshAt: 150 * time.Second,
		trigger:   viaSlowVerify,
	},
	{
		name:      "serve_stale+prefer_positive/immediate",
		extra:     "\tserve_stale 1h immediate\n\tserve_stale_policy prefer_positive",
		refreshAt: 150 * time.Second,
		trigger:   viaBackground,
	},
	{
		name:      "serve_stale+prefer_positive/verify",
		extra:     "\tserve_stale 1h verify\n\tserve_stale_policy prefer_positive",
		refreshAt: 150 * time.Second,
		trigger:   viaForeground,
	},
}

type exclusionCase struct {
	name     string
	disable  string // "denial" or "success"
	seed     int32  // response for the allowed category
	excluded int32  // response in the disabled category
}

var exclusionCases = []exclusionCase{
	{name: "disable denial: positive->NXDOMAIN", disable: Denial, seed: respPositive, excluded: respNXDomain},
	{name: "disable success: NXDOMAIN->positive", disable: Success, seed: respNXDomain, excluded: respPositive},
}

// inExcludedCache reports whether name is stored in the cache the case disables.
func (tc exclusionCase) inExcludedCache(e *refreshEnv, name string) bool {
	if tc.disable == Denial {
		return e.inN(name)
	}
	return e.inP(name)
}

func (tc exclusionCase) inAllowedCache(e *refreshEnv, name string) bool {
	if tc.disable == Denial {
		return e.inP(name)
	}
	return e.inN(name)
}

func (tc exclusionCase) allowedItem(e *refreshEnv, name string) (*item, bool) {
	if tc.disable == Denial {
		return e.pItem(name)
	}
	return e.nItem(name)
}

// TestDisableExclusionOrdinaryMiss is the control for the matrix: an ordinary
// miss must honor the exclusion, and the same response outside the excluded
// zone must still be cached.
func TestDisableExclusionOrdinaryMiss(t *testing.T) {
	for _, tc := range exclusionCases {
		for _, name := range []string{exclName, ctrlName} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, name), func(t *testing.T) {
				e := newRefreshEnv(t, tc.disable, "")
				e.mode.Store(tc.excluded)

				first := e.query(name)
				second := e.query(name)

				wantStored := name == ctrlName
				if got := tc.inExcludedCache(e, name); got != wantStored {
					t.Errorf("stored in %s cache = %v, want %v", tc.disable, got, wantStored)
				}
				wantCalls := int32(2)
				if wantStored {
					wantCalls = 1
				}
				if got := e.calls.Load(); got != wantCalls {
					t.Errorf("upstream calls = %d, want %d", got, wantCalls)
				}
				t.Logf("miss | %-38s | %-26s | stored=%v calls=%d client=%s/%s", tc.name, name, tc.inExcludedCache(e, name), e.calls.Load(), rcodeName(first), rcodeName(second))
			})
		}
	}
}

// TestDisableExclusionOnRefresh is the matrix from the finding. For every
// refresh path it seeds the allowed cache with an ordinary query, flips the
// upstream to the opposite category, drives the refresh, and then inspects
// both caches for the exact key.
func TestDisableExclusionOnRefresh(t *testing.T) {
	for _, rp := range refreshPaths {
		for _, tc := range exclusionCases {
			for _, name := range []string{exclName, ctrlName} {
				t.Run(fmt.Sprintf("%s/%s/%s", rp.name, tc.name, name), func(t *testing.T) {
					e := newRefreshEnv(t, tc.disable, rp.extra)

					// Seed the allowed cache through the ordinary path.
					e.setNow(0)
					e.mode.Store(tc.seed)
					seedWire := e.query(name)
					e.drain()
					seed, ok := tc.allowedItem(e, name)
					if !ok {
						t.Fatalf("precondition: seed response was not stored in the allowed cache")
					}
					if tc.inExcludedCache(e, name) {
						t.Fatalf("precondition: excluded cache is not empty after seeding")
					}
					if got := e.calls.Load(); got != 1 {
						t.Fatalf("precondition: upstream calls after seed = %d, want 1", got)
					}

					// Change the source, then drive the refresh path.
					e.mode.Store(tc.excluded)
					e.setNow(rp.refreshAt)
					wire := rp.trigger(e, name, seed)

					if got := e.calls.Load(); got != 2 {
						t.Fatalf("upstream calls after refresh = %d, want exactly 2 (seed + one refresh)", got)
					}

					stored := tc.inExcludedCache(e, name)
					wantStored := name == ctrlName // control name is not excluded and must cache normally
					if stored != wantStored {
						if wantStored {
							t.Errorf("control: refreshed %s response outside the excluded zone was not cached", tc.disable)
						} else {
							t.Errorf("BYPASS: refresh stored a %s response for %s although `disable %s %s` is configured",
								tc.disable, name, tc.disable, exclZone)
						}
					}
					t.Logf("%-55s | %-38s | %-26s | seed=%s wire=%s | stored_in_%s_cache=%v allowed_cache_kept=%v calls=%d",
						rp.name, tc.name, name, rcodeName(seedWire), rcodeName(wire), tc.disable, stored, tc.inAllowedCache(e, name), e.calls.Load())
				})
			}
		}
	}
}

// TestDisableDenialRefreshFollowUpClient shows what a later client observes in
// the typical incident shape: a positive entry, a `disable denial` zone, the
// source briefly answers NXDOMAIN during a refresh and then recovers. Once the
// positive entry can no longer answer, the next handler must be consulted and
// the client must see the recovered positive answer.
func TestDisableDenialRefreshFollowUpClient(t *testing.T) {
	tests := []struct {
		name     string
		path     refreshPath
		followAt time.Duration
	}{
		// Prefetch: the positive entry (TTL 100) has expired at +105s and there
		// is no stale window, so a correct cache must go back to the upstream.
		{"prefetch", refreshPaths[0], 105 * time.Second},
		// Stale paths: stale positive is still within the 1h window.
		{"serve_stale/immediate", refreshPaths[1], 155 * time.Second},
		{"serve_stale/verify+timeout(slow upstream, bg completes)", refreshPaths[4], 155 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newRefreshEnv(t, Denial, tt.path.extra)

			e.setNow(0)
			e.mode.Store(respPositive)
			e.query(exclName)
			e.drain()
			seed, _ := e.pItem(exclName)

			// The source answers NXDOMAIN to the refresh only.
			e.mode.Store(respNXDomain)
			e.setNow(tt.path.refreshAt)
			tt.path.trigger(e, exclName, seed)

			// The source recovers.
			e.mode.Store(respPositive)
			e.setNow(tt.followAt)
			callsBefore := e.calls.Load()
			got := e.query(exclName)
			e.settle(seed)
			followCalls := e.calls.Load() - callsBefore

			t.Logf("follow-up at +%s: client=%s ncache_has_entry=%v upstream_calls_for_follow_up=%d",
				tt.followAt, rcodeName(got), e.inN(exclName), followCalls)
			if got.Rcode != dns.RcodeSuccess {
				t.Errorf("client received %s from CoreDNS after the source recovered; the denial must not have been cacheable in a `disable denial` zone", rcodeName(got))
			}
		})
	}
}
