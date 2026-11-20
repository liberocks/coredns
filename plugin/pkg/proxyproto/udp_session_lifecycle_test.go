package proxyproto

// Lifecycle fixture for the UDP session cache.
//
// A session cache must not outlive the PacketConn that created it. The previous
// implementation used golang-lru/v2 expirable.LRU (v2.0.7), whose cleanup
// goroutine can never be stopped and keeps the cache reachable forever, so a
// closed listener left a worker and its cache behind.
//
// These tests count goroutines process-wide, so they are deliberately NOT
// parallel and take a baseline first. lruWorkers() looks for that dependency's
// worker symbol and guards against it (or any cache like it) coming back.

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
func ppv2Datagram(tb testing.TB, src *net.UDPAddr, payload []byte) []byte {
	tb.Helper()
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr:        src,
		DestinationAddr:   udpAddr("192.0.2.1", 53),
	}
	b, err := h.Format()
	if err != nil {
		tb.Fatal(err)
	}
	return append(b, payload...)
}

func useAll(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) { return proxyproto.USE, nil }

// serveOneSession pushes one ordinary tracked datagram (PPv2 header + payload
// from a Spectrum-side remote address) through ReadFrom, which lazily creates
// the session cache on the first eligible session.
func serveOneSession(tb testing.TB, pc *PacketConn, fake *fakePacketConn, remote, client *net.UDPAddr) {
	tb.Helper()
	fake.push(ppv2Datagram(tb, client, []byte("dns-payload")), remote)
	buf := make([]byte, 512)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		tb.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "dns-payload" {
		tb.Fatalf("payload = %q", buf[:n])
	}
	if got := addr.String(); got != client.String() {
		tb.Fatalf("addr = %s, want real client %s", got, client)
	}
}

func newTracked(ttl time.Duration) (*PacketConn, *fakePacketConn) {
	fake := newFakePacketConn()
	return &PacketConn{PacketConn: fake, ConnPolicy: useAll, UDPSessionTrackingTTL: ttl}, fake
}

// The wrapper has no File(), so caddy cannot hand it to the next instance on a
// reload: every reload creates a new wrapper and therefore a new session table.
func TestWrapperMethodSet(t *testing.T) {
	var pc any = &PacketConn{}
	if _, ok := pc.(interface{ File() (*os.File, error) }); ok {
		t.Fatal("PacketConn unexpectedly has File(); caddy could reuse it across reload")
	}
}

// The first eligible session creates the table lazily, starts no worker, and
// Close leaves nothing reachable: once the wrapper is dropped the table is
// collected. Before the fix a worker kept it alive forever.
func TestSessionCacheReleasedWithConn(t *testing.T) {
	base := lruWorkers()
	pc, fake := newTracked(200 * time.Millisecond)
	if pc.sessionCache != nil {
		t.Fatal("cache created before any session")
	}

	serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 5000), udpAddr("198.51.100.7", 40000))
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("workers after first tracked session = +%d, want +0", got)
	}
	if pc.sessionCache == nil || pc.sessionCache.Len() != 1 {
		t.Fatal("expected one tracked session")
	}
	table := weak.Make(pc.sessionCache)

	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.closes.Load() != 1 {
		t.Fatalf("underlying Close calls = %d, want 1", fake.closes.Load())
	}

	time.Sleep(3 * 200 * time.Millisecond)
	settle()
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("workers after Close+GC = +%d, want +0", got)
	}
	if table.Value() != nil {
		t.Fatal("session table still reachable after its PacketConn was closed and dropped")
	}
}

// Close before any session is a no-op for the cache: nothing was started.
func TestCloseBeforeInit(t *testing.T) {
	base := lruWorkers()
	pc, fake := newTracked(time.Second)
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	settle()
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
		t.Fatalf("workers = +%d, want +0", got)
	}
}

// No table is created without tracking, or for traffic that carries no header.
func TestNoSessionCacheWhenIneligible(t *testing.T) {
	fake := newFakePacketConn()
	off := &PacketConn{PacketConn: fake, ConnPolicy: useAll}
	serveOneSession(t, off, fake, udpAddr("10.0.0.1", 5000), udpAddr("198.51.100.7", 40000))
	off.Close()
	if off.sessionCache != nil {
		t.Fatal("cache created with tracking disabled")
	}

	pc, fake2 := newTracked(time.Second)
	fake2.push([]byte("no-header-payload"), udpAddr("10.0.0.2", 5001))
	if _, _, err := pc.ReadFrom(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	pc.Close()
	if pc.sessionCache != nil {
		t.Fatal("headerless traffic created a cache")
	}
}

// Two sequential wrappers (a listener replacement): each has its own session
// state, no worker exists at any point, and after both are closed and dropped
// nothing of either is reachable.
func TestSequentialWrappersLeaveNothingBehind(t *testing.T) {
	const n = 5
	base := lruWorkers()
	tables := make([]weak.Pointer[sessionTable], 0, n)
	firstRemote := udpAddr("10.0.0.1", 5000)

	for i := range n {
		pc, fake := newTracked(time.Minute)
		serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 5000+i), udpAddr("198.51.100.7", 40000+i))
		tables = append(tables, weak.Make(pc.sessionCache))
		if i == 1 {
			if _, ok := pc.lookupSession(firstRemote); ok {
				t.Fatal("second wrapper observed the first wrapper's session")
			}
		}
		pc.Close()
		if got := lruWorkers() - base; got != 0 {
			t.Fatalf("after wrapper %d closed: workers=+%d, want +0", i, got)
		}
	}
	settle()
	for i, w := range tables {
		if w.Value() != nil {
			t.Fatalf("session table %d still reachable after close", i)
		}
	}
}

// Entries expire without any background worker: expiry is applied on access.
func TestSessionExpiresWithoutWorker(t *testing.T) {
	base := lruWorkers()
	ttl := 50 * time.Millisecond
	pc := newTestPacketConn(ttl, 0)
	for i := range 20 {
		pc.storeSession(udpAddr("10.0.0.1", 7000+i), testHeader(udpAddr("198.51.100.8", 50000+i)))
	}
	if got := pc.sessionCache.Len(); got != 20 {
		t.Fatalf("Len = %d, want 20", got)
	}
	time.Sleep(3 * ttl)
	if got := pc.sessionCache.Len(); got != 0 {
		t.Fatalf("Len after expiry = %d, want 0", got)
	}
	if _, ok := pc.lookupSession(udpAddr("10.0.0.1", 7000)); ok {
		t.Fatal("expired session was returned")
	}
	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("workers = +%d, want +0", got)
	}
}

// A lookup refreshes only the touched session; the others still expire on time.
func TestSessionRefreshKeepsOrdering(t *testing.T) {
	ttl := 120 * time.Millisecond
	pc := newTestPacketConn(ttl, 0)
	a, b := udpAddr("10.0.0.1", 1), udpAddr("10.0.0.1", 2)
	pc.storeSession(a, testHeader(udpAddr("198.51.100.1", 1)))
	pc.storeSession(b, testHeader(udpAddr("198.51.100.2", 2)))
	for range 4 { // keep a alive past 2x ttl
		time.Sleep(ttl / 3)
		if _, ok := pc.lookupSession(a); !ok {
			t.Fatal("refreshed session expired early")
		}
	}
	if _, ok := pc.lookupSession(b); ok {
		t.Fatal("untouched session did not expire")
	}
}

// The table is safe for concurrent use and never exceeds its capacity.
func TestSessionTableConcurrentBounded(t *testing.T) {
	pc := newTestPacketConn(time.Second, 64)
	pc.ensureSessionCache()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 2000 {
				r := udpAddr("10.0.0.1", 1000+(g*2000+i)%500)
				pc.storeSession(r, testHeader(udpAddr("198.51.100.9", 1)))
				pc.lookupSession(r)
			}
		})
	}
	wg.Wait()
	if got := pc.sessionCache.Len(); got > 64 {
		t.Fatalf("Len = %d exceeds capacity 64", got)
	}
}

// Retention after close: with the reproduction in the previous commit each
// closed wrapper kept ~8 KB of heap (plus a goroutine) alive. Now the heap
// profile must show essentially no live bytes allocated by newSessionTable.
func TestNoRetainedBytesAfterClose(t *testing.T) {
	const (
		n        = 200
		sessions = 50
	)
	prev := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = prev }()

	base := lruWorkers()
	for i := range n {
		pc, fake := newTracked(time.Minute)
		serveOneSession(t, pc, fake, udpAddr("10.0.0.1", 6000), udpAddr("198.51.100.7", 40000))
		for j := range sessions {
			pc.storeSession(udpAddr("10.1.0.1", 10000+j), testHeader(udpAddr("198.51.100.8", 50000+i)))
		}
		pc.Close()
	}
	settle()
	runtime.GC()
	runtime.GC()

	if got := lruWorkers() - base; got != 0 {
		t.Fatalf("workers = +%d, want +0", got)
	}
	recs := make([]runtime.MemProfileRecord, 8192)
	cnt, ok := runtime.MemProfile(recs, true)
	if !ok {
		t.Fatalf("MemProfile buffer too small (%d)", cnt)
	}
	var inuse int64
	for _, r := range recs[:cnt] {
		frames := runtime.CallersFrames(r.Stack())
		for {
			f, more := frames.Next()
			if strings.Contains(f.Function, "proxyproto.newSessionTable") {
				inuse += r.InUseBytes()
				break
			}
			if !more {
				break
			}
		}
	}
	t.Logf("live bytes allocated by newSessionTable after %d closed wrappers: %d", n, inuse)
	// Leaking would retain >= n * ~8 KB = ~1.6 MB.
	if inuse > 64<<10 {
		t.Fatalf("%d bytes still live from closed wrappers' session tables", inuse)
	}
}
