package dnsserver

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/metrics/vars"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// gateWriter is the raw writer under the guard. Writes block on gate (when set),
// and it records how many are in progress at once.
type gateWriter struct {
	gate     chan struct{}
	cur, max atomic.Int64
	written  atomic.Int64
}

func (g *gateWriter) Write(p []byte) (int, error) {
	c := g.cur.Add(1)
	for {
		m := g.max.Load()
		if c <= m || g.max.CompareAndSwap(m, c) {
			break
		}
	}
	defer g.cur.Add(-1)
	if g.gate != nil {
		<-g.gate
	}
	g.written.Add(1)
	return len(p), nil
}

func newDropCounter() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: "test_dropped_total"})
}

func TestGuardUDPWritesPassesThroughBelowLimit(t *testing.T) {
	dropped := newDropCounter()
	raw := &gateWriter{}
	w := guardUDPWrites(nil, 2, dropped)(raw)
	for range 10 { // sequential writes never exceed one pending
		if n, err := w.Write([]byte("abc")); n != 3 || err != nil {
			t.Fatalf("Write = %d, %v; want 3, nil", n, err)
		}
	}
	if got := raw.written.Load(); got != 10 {
		t.Errorf("underlying writes = %d, want 10", got)
	}
	if got := testutil.ToFloat64(dropped); got != 0 {
		t.Errorf("dropped = %v, want 0", got)
	}
}

func TestGuardUDPWritesDropsBeyondLimit(t *testing.T) {
	const limit = 3
	dropped := newDropCounter()
	raw := &gateWriter{gate: make(chan struct{})}
	dec := guardUDPWrites(nil, limit, dropped)

	var wg sync.WaitGroup
	for range limit {
		wg.Go(func() { dec(raw).Write([]byte("x")) }) //nolint:errcheck
	}
	for raw.cur.Load() != limit {
		runtime.Gosched()
	}

	// The next write must return at once, report success and not reach the socket.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if n, err := dec(raw).Write([]byte("over")); n != 4 || err != nil {
			t.Errorf("dropped Write = %d, %v; want 4, nil", n, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a write beyond the limit blocked instead of being dropped")
	}
	if got := testutil.ToFloat64(dropped); got != 1 {
		t.Errorf("dropped = %v, want 1", got)
	}

	close(raw.gate)
	wg.Wait()
	if got := raw.written.Load(); got != limit {
		t.Errorf("underlying writes = %d, want %d", got, limit)
	}
	// Capacity is released: a later write goes through.
	dec(raw).Write([]byte("later")) //nolint:errcheck
	if got := raw.written.Load(); got != limit+1 {
		t.Errorf("underlying writes after release = %d, want %d", got, limit+1)
	}
}

func TestGuardUDPWritesBoundsConcurrentWriters(t *testing.T) {
	const limit, writers = 8, 500
	dropped := newDropCounter()
	raw := &gateWriter{gate: make(chan struct{})}
	dec := guardUDPWrites(nil, limit, dropped)

	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() { dec(raw).Write([]byte("x")) }) //nolint:errcheck
	}
	for testutil.ToFloat64(dropped) != writers-limit {
		runtime.Gosched()
	}
	close(raw.gate)
	wg.Wait()

	if got := raw.max.Load(); got > limit {
		t.Errorf("max concurrent underlying writes = %d, want <= %d", got, limit)
	}
	if w, d := raw.written.Load(), int64(testutil.ToFloat64(dropped)); w+d != writers {
		t.Errorf("written %d + dropped %d != %d writers", w, d, writers)
	}
}

func TestGuardUDPWritesAppliesConfiguredDecorator(t *testing.T) {
	raw := &gateWriter{}
	var wrapped atomic.Int64
	next := func(w dns.Writer) dns.Writer {
		wrapped.Add(1)
		return w
	}
	w := guardUDPWrites(next, 1, newDropCounter())(raw)
	w.Write([]byte("x")) //nolint:errcheck
	if wrapped.Load() != 1 || raw.written.Load() != 1 {
		t.Errorf("decorator applied %d times, underlying writes %d; want 1 and 1", wrapped.Load(), raw.written.Load())
	}
}

// countingPlugin answers every query and counts handler entries and returns.
type countingPlugin struct{ entered, returned *atomic.Int64 }

func (countingPlugin) Name() string { return "counting" }
func (p countingPlugin) ServeDNS(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	p.entered.Add(1)
	defer p.returned.Add(1)
	return dns.RcodeSuccess, w.WriteMsg(new(dns.Msg).SetReply(r))
}

// TestServePacketBoundsPendingWritesOnStalledSocket stalls one write on the real
// listener socket, as a sendto blocked in the kernel would, and floods it. The
// handlers beyond the limit must return and be counted instead of parking in the
// socket's write queue; once the stall ends, the queued ones are written.
func TestServePacketBoundsPendingWritesOnStalledSocket(t *testing.T) {
	const limit, queries = 32, 2000

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var entered, returned atomic.Int64
	ready := make(chan struct{})
	cfg := testConfig("dns", countingPlugin{&entered, &returned})
	cfg.UDPDecorateWriterFunc = func(*Server) dns.DecorateWriter { close(ready); return nil }
	srv, err := NewServer("127.0.0.1:0", []*Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	srv.udpMaxPendingWrites = limit
	served := make(chan error, 1)
	go func() { served <- srv.ServePacket(conn) }()
	<-ready
	// Registered before the stall's release, so (LIFO) the release runs first:
	// Stop waits for handlers that are parked on the held write lock.
	defer func() {
		_ = srv.Stop()
		<-served
	}()

	dropped := vars.UDPWriteDropped.WithLabelValues(srv.Address())
	droppedBefore := testutil.ToFloat64(dropped)

	// Park one write in progress: the callback holds the fd's write lock.
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	holding, release, held := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(held)
		rc.Write(func(uintptr) bool { close(holding); <-release; return true }) //nolint:errcheck
	}()
	<-holding
	var once sync.Once
	releaseOnce := func() { once.Do(func() { close(release) }); <-held }
	defer releaseOnce()

	base := runtime.NumGoroutine()
	client, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	pkt, _ := new(dns.Msg).SetQuestion("example.com.", dns.TypeA).Pack()
	for sent := 0; sent < queries; {
		for range 100 {
			if _, err := client.Write(pkt); err != nil {
				t.Fatal(err)
			}
			sent++
		}
		waitUntil(t, "server to read the batch", func() bool { return entered.Load() >= int64(sent) })
	}

	// Everything beyond the limit returns while the stall is still in place.
	waitUntil(t, "handlers beyond the limit to return", func() bool { return returned.Load() >= queries-limit })
	if got := returned.Load(); got != queries-limit {
		t.Errorf("returned = %d during the stall, want %d (the rest wait for the socket)", got, queries-limit)
	}
	if grew := runtime.NumGoroutine() - base; grew > limit+16 {
		t.Errorf("goroutines grew by %d during the stall, want about %d", grew, limit)
	}
	if got := int(testutil.ToFloat64(dropped) - droppedBefore); got != queries-limit {
		t.Errorf("dropped = %d, want %d", got, queries-limit)
	}

	releaseOnce()
	waitUntil(t, "queued handlers to finish after the stall", func() bool { return returned.Load() == queries })
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
