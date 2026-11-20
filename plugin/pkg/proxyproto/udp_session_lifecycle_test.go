package proxyproto

// Lifecycle fixture for the UDP session cache (finding 05).
//
// The tests in this file are deliberately NOT parallel: they count goroutines
// process-wide and take a baseline first, because other tests in this package
// create session caches that can never be stopped (that is the subject here).
//
// TestRepro* tests assert the behaviour observed at the pinned dependency
// (golang-lru/v2 v2.0.7). TestSessionCacheWorkerStopsOnClose asserts the
// contract a fix must satisfy; it is skipped unless PROXYPROTO_LIFECYCLE_CONTRACT=1
// because it fails today.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/hashicorp/golang-lru/v2/expirable"
	proxyproto "github.com/pires/go-proxyproto"
)

const lruWorkerSymbol = "golang-lru/v2/expirable.NewLRU"

// lruWorkers returns the number of live goroutines whose stack is rooted at the
// dependency's cleanup worker (the func literal started by expirable.NewLRU).
func lruWorkers() int {
	var buf bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&buf, 2)
	n := 0
	for rec := range strings.SplitSeq(buf.String(), "\n\n") {
		if strings.Contains(rec, lruWorkerSymbol) {
			n++
		}
	}
	return n
}

// settle gives finalizers, timers and goroutine exits a chance to run.
func settle() {
	for range 3 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

// fakePacketConn is an in-memory net.PacketConn. ReadFrom returns queued
// datagrams, then blocks until Close. It records every Close call.
type fakePacketConn struct {
	mu     sync.Mutex
	queue  []fakeDatagram
	closed chan struct{}
	closes atomic.Int32
	once   sync.Once
}

type fakeDatagram struct {
	data []byte
	from net.Addr
}

func newFakePacketConn() *fakePacketConn { return &fakePacketConn{closed: make(chan struct{})} }

func (f *fakePacketConn) push(data []byte, from net.Addr) {
	f.mu.Lock()
	f.queue = append(f.queue, fakeDatagram{data, from})
	f.mu.Unlock()
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	if len(f.queue) > 0 {
		d := f.queue[0]
		f.queue = f.queue[1:]
		f.mu.Unlock()
		return copy(p, d.data), d.from, nil
	}
	f.mu.Unlock()
	<-f.closed
	return 0, nil, net.ErrClosed
}

func (f *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (f *fakePacketConn) Close() error {
	f.closes.Add(1)
	f.once.Do(func() { close(f.closed) })
	return nil
}
func (f *fakePacketConn) LocalAddr() net.Addr              { return udpAddr("127.0.0.1", 53) }
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

// ppv2Datagram builds a PROXY v2 UDP/IPv4 header for src followed by payload.
func ppv2Datagram(t testing.TB, src *net.UDPAddr, payload []byte) []byte {
	t.Helper()
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr:        src,
		DestinationAddr:   udpAddr("192.0.2.1", 53),
	}
	b, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	return append(b, payload...)
}

func useAll(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.USE, nil }

// serveOneSession pushes one ordinary tracked datagram (PPv2 header + payload
// from a Spectrum-side remote address) through ReadFrom, which lazily creates
// the session cache on the first eligible session.
func serveOneSession(t testing.TB, pc *PacketConn, fake *fakePacketConn, remote, client *net.UDPAddr) {
	t.Helper()
	fake.push(ppv2Datagram(t, client, []byte("dns-payload")), remote)
	buf := make([]byte, 512)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "dns-payload" {
		t.Fatalf("payload = %q", buf[:n])
	}
	if got := addr.String(); got != client.String() {
		t.Fatalf("addr = %s, want real client %s", got, client)
	}
}

func newTracked(ttl time.Duration) (*PacketConn, *fakePacketConn) {
	fake := newFakePacketConn()
	return &PacketConn{PacketConn: fake, ConnPolicy: useAll, UDPSessionTrackingTTL: ttl}, fake
}

// Close reaches only the embedded connection: the wrapper has no Close of its
// own, no File() (so Caddy cannot hand it across a reload), and no cache hook.
func TestReproWrapperMethodSet(t *testing.T) {
	var pc any = &PacketConn{}
	if _, ok := pc.(interface{ File() (*os.File, error) }); ok {
		t.Fatal("PacketConn unexpectedly has File(); Caddy could reuse it across reload")
	}
	if _, ok := pc.(interface{ CloseSessions() }); ok {
		t.Fatal("unexpected session cleanup hook")
	}
}

// Lazy start: nothing is started by constructing or closing the wrapper; the
// worker starts on the first eligible session, and Close does not stop it.
func TestReproWorkerSurvivesClose(t *testing.T) {
	base := lruWorkers()
	pc, fake := newTracked(200 * time.Millisecond)

	if got := lruWorkers(); got != base {
		t.Fatalf("workers after construction = +%d, want +0 (lazy start)", got-base)
	}

	serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 5000), udpAddr("198.51.100.7", 40000))
	if got := lruWorkers() - base; got != 1 {
		t.Fatalf("workers after first tracked session = %d, want 1", got)
	}
	cache := weak.Make(pc.sessionCache)

	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.closes.Load() != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", fake.closes.Load())
	}

	// Drop every reference we hold, wait several TTLs (entries expire), GC.
	pc, fake = nil, nil
	time.Sleep(3 * 200 * time.Millisecond)
	settle()

	if got := lruWorkers() - base; got != 1 {
		t.Fatalf("workers after Close+GC+3xTTL = %d, want 1 (worker survives)", got)
	}
	lru := cache.Value()
	if lru == nil {
		t.Fatal("session cache was collected; expected the worker to keep it reachable")
	}
	if n := lru.Len(); n != 0 {
		t.Fatalf("entries after expiry = %d, want 0 (entries expire; only the container leaks)", n)
	}
	t.Logf("after Close, GC and 3xTTL: workers=+%d, cache still reachable, entries=%d", lruWorkers()-base, lru.Len())
}

// Control for the weak-pointer technique: an expirable.LRU WITHOUT a worker
// (ttl 0) is collected once unreferenced, so reachability above is attributable
// to the worker and not to the measurement.
func TestReproControlLRUWithoutWorkerIsCollected(t *testing.T) {
	base := lruWorkers()
	lru := expirable.NewLRU[string, int](10, nil, 0)
	lru.Add("k", 1)
	w := weak.Make(lru)
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("ttl=0 LRU started %d workers, want 0", got)
	}
	lru = nil
	settle()
	if w.Value() != nil {
		t.Fatal("worker-less LRU was not collected; weak-pointer technique is unreliable")
	}
}

// Close before any session is a no-op for the cache: nothing was started.
func TestReproCloseBeforeInit(t *testing.T) {
	base := lruWorkers()
	pc, fake := newTracked(time.Second)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	settle()
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("workers after Close before init = %d, want 0", got)
	}
	if pc.sessionCache != nil {
		t.Fatal("cache created without a session")
	}
	if _, _, err := pc.ReadFrom(make([]byte, 16)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close err = %v", err)
	}
	if fake.closes.Load() != 1 {
		t.Fatalf("underlying Close calls = %d", fake.closes.Load())
	}
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("a closed, never-initialised wrapper must not start a worker, got %d", got)
	}
}

// Set-aside conditions: no worker without tracking, and none for a header that
// does not create a session (LOCAL command).
func TestReproNoWorkerWhenIneligible(t *testing.T) {
	base := lruWorkers()

	// Tracking disabled (TTL 0): header traffic never touches the cache.
	fake := newFakePacketConn()
	off := &PacketConn{PacketConn: fake, ConnPolicy: useAll}
	serveOneSession(t, off, fake, udpAddr("10.0.0.1", 5000), udpAddr("198.51.100.7", 40000))
	off.Close()

	// Tracking enabled but only headerless traffic: lookupSession never creates.
	pc, fake2 := newTracked(time.Second)
	fake2.push([]byte("no-header-payload"), udpAddr("10.0.0.2", 5001))
	if _, _, err := pc.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	pc.Close()

	settle()
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("ineligible traffic started %d workers, want 0", got)
	}
}

// Two sequential wrappers (a listener replacement): each owns its own session
// state and its own never-ending worker.
func TestReproSequentialWrappersAccumulateWorkers(t *testing.T) {
	const n = 5
	base := lruWorkers()
	var caches []weak.Pointer[expirable.LRU[string, *proxyproto.Header]]
	var firstRemote = udpAddr("10.0.0.1", 5000)

	for i := range n {
		pc, fake := newTracked(time.Minute)
		serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 5000+i), udpAddr("198.51.100.7", 40000+i))
		caches = append(caches, weak.Make(pc.sessionCache))
		if i == 1 {
			// Session state is per wrapper: wrapper 1 must not see wrapper 0's session.
			if _, ok := pc.lookupSession(firstRemote); ok {
				t.Fatal("second wrapper observed the first wrapper's session")
			}
		}
		pc.Close()
		if got := lruWorkers() - base; got != i+1 {
			t.Fatalf("after wrapper %d closed: workers=+%d, want +%d", i, got, i+1)
		}
	}
	settle()
	if got := lruWorkers() - base; got != n {
		t.Fatalf("after all %d wrappers closed: workers=+%d, want +%d (none exit)", n, got, n)
	}
	for i, c := range caches {
		if c.Value() == nil {
			t.Fatalf("cache %d collected", i)
		}
	}
	t.Logf("%d sequential wrappers closed -> %d surviving workers (expected 0 after a fix)", n, lruWorkers()-base)
}

// Retained size: measure what one leaked, empty (post-expiry) cache costs, and
// attribute live heap to the CoreDNS allocation site via the heap profile.
func TestReproRetainedBytesPerLeakedCache(t *testing.T) {
	const (
		n        = 200
		sessions = 50
		ttl      = 100 * time.Millisecond
	)
	prev := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = prev }()

	readMem := func() runtime.MemStats {
		settle()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m
	}
	base := lruWorkers()
	before := readMem()

	for i := range n {
		pc, fake := newTracked(ttl)
		serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 6000), udpAddr("198.51.100.7", 40000))
		for j := range sessions {
			pc.storeSession(udpAddr("10.1.0.1", 10000+j), testHeader(udpAddr("198.51.100.8", 50000+i)))
		}
		pc.Close()
	}
	live := readMem() // entries still present (<= ttl old)
	time.Sleep(4 * ttl)
	expired := readMem()

	if got := lruWorkers() - base; got != n {
		t.Fatalf("workers=+%d, want +%d", got, n)
	}
	per := func(a, b uint64) float64 { return (float64(a) - float64(b)) / n }
	t.Logf("n=%d leaked caches, %d sessions each, ttl=%s", n, sessions, ttl)
	t.Logf("  heap/cache with entries   : %.0f B", per(live.HeapAlloc, before.HeapAlloc))
	t.Logf("  heap/cache after expiry   : %.0f B  (retained container)", per(expired.HeapAlloc, before.HeapAlloc))
	t.Logf("  goroutine stack/cache     : %.0f B", per(expired.StackInuse, before.StackInuse))

	// Heap profile: in-use bytes whose allocation stack passes through
	// CoreDNS's ensureSessionCache -> expirable.NewLRU.
	runtime.GC()
	runtime.GC()
	recs := make([]runtime.MemProfileRecord, 4096)
	cnt, ok := runtime.MemProfile(recs, true)
	if !ok {
		t.Fatalf("MemProfile buffer too small (%d)", cnt)
	}
	var inuse int64
	for _, r := range recs[:cnt] {
		var viaCoreDNS, viaNewLRU bool
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			viaCoreDNS = viaCoreDNS || strings.Contains(f.Function, "proxyproto.(*PacketConn).ensureSessionCache")
			viaNewLRU = viaNewLRU || strings.Contains(f.Function, "expirable.NewLRU")
			if !more {
				break
			}
		}
		if viaCoreDNS && viaNewLRU {
			inuse += r.InUseBytes()
		}
	}
	// The profile covers every cache this test binary leaked (earlier tests too).
	t.Logf("  heap profile in-use via ensureSessionCache->NewLRU: %d B across %d live workers (%.0f B/worker)",
		inuse, lruWorkers(), float64(inuse)/float64(lruWorkers()))
	if inuse <= 0 {
		t.Fatal("heap profile shows no live bytes attributable to ensureSessionCache->NewLRU")
	}
}

// ---- Contract a fix must meet (fails today; skipped by default) -------------

// TestSessionCacheWorkerStopsOnClose states the lifecycle contract from the task:
// closing a wrapper must stop its worker; the next wrapper has independent
// state; after closing both the active worker count is back to the baseline.
func TestSessionCacheWorkerStopsOnClose(t *testing.T) {
	if os.Getenv("PROXYPROTO_LIFECYCLE_CONTRACT") != "1" {
		t.Skip("contract test; fails until the session cache is released on Close (set PROXYPROTO_LIFECYCLE_CONTRACT=1)")
	}
	base := lruWorkers()

	a, fa := newTracked(time.Minute)
	serveOneSession(t, a, fa, udpAddr("10.0.0.1", 5000), udpAddr("198.51.100.7", 40000))
	a.Close()
	waitWorkers(t, base, "after first wrapper closed")

	b, fb := newTracked(time.Minute)
	serveOneSession(t, b, fb, udpAddr("10.0.0.1", 5001), udpAddr("198.51.100.7", 40001))
	if _, ok := b.lookupSession(udpAddr("10.0.0.1", 5000)); ok {
		t.Fatal("second wrapper observed the first wrapper's session")
	}
	if got := lruWorkers() - base; got != 1 {
		t.Fatalf("workers with one live wrapper = %d, want 1", got)
	}
	b.Close()
	waitWorkers(t, base, "after both wrappers closed")
}

func waitWorkers(t *testing.T, want int, when string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		runtime.GC()
		if lruWorkers() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: workers=%d, want %d", when, lruWorkers(), want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
