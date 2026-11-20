package shed

// Evidence tests for the UDP response writer backlog (Finding 01).
//
// Unlike fdmutex_test.go, which drives raw UDPConn writers, these tests run the
// real miekg/dns UDP server loop (one goroutine per datagram, handler writes
// through response.WriteMsg) over a loopback socket, and stall the one thing
// the finding is about: the write path of the listener's file descriptor.
//
// The stall is injected deterministically, with no throughput assumption: the
// test parks one write in progress through SyscallConn().Write, which holds the
// fd's real fdMutex write lock exactly as a sendto blocked in the kernel does.
// Every other writer on that socket then queues behind it.
//
// The same harness runs three ways:
//
//   - TestUnshedWritersPileUpOnStalledSocket: no decorator. Handlers pile up in
//     the fd write wait queue, one goroutine and its request state each.
//   - TestShedBoundsWritersOnStalledSocket: the plugin's decorator and
//     ServeDNS. One writer, a bounded queue, handlers return, drops counted.
//   - TestStalledWriteControls: conditions under which there is no pile-up.
//
// Every scenario logs one "EVIDENCE" line so the numbers can be collected with
// `go test -v -run ... | grep EVIDENCE`. Scale is 20k datagrams by default and
// 200k under SHED_FLOOD_TEST=1.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/core/dnsserver"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const (
	backlogN      = 20_000  // datagrams per scenario by default
	backlogBigN   = 200_000 // datagrams under SHED_FLOOD_TEST=1
	backlogBatch  = 500     // sender pacing: wait for the server to read each batch
	backlogWaitTO = 60 * time.Second
)

func backlogDatagrams() int {
	if os.Getenv(floodEnv) != "" {
		return backlogBigN
	}
	return backlogN
}

// ---- stall injection ------------------------------------------------------

// holdWriteLock parks one write in progress on conn's fd: the callback runs
// with the fd's write lock held, as a sendto blocked in the kernel would. The
// returned release is idempotent and waits for the holder goroutine to exit.
func holdWriteLock(t *testing.T, conn *net.UDPConn) (release func()) {
	t.Helper()
	rc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	holding, rel, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		rc.Write(func(uintptr) bool { //nolint:errcheck // lock-holding callback only
			close(holding)
			<-rel
			return true
		})
	}()
	<-holding
	var once sync.Once
	release = func() {
		once.Do(func() { close(rel) })
		<-done
	}
	t.Cleanup(release)
	return release
}

// ---- downstream write gauge ----------------------------------------------

// gauge counts downstream writes: how many are in progress right now, the
// high-water mark, and how many completed. It sits below the decorator, so with
// shed installed it observes only the writer goroutine's writes.
type gauge struct {
	cur, max, done atomic.Int64
}

func (g *gauge) wrap(w dns.Writer) dns.Writer { return &gaugeWriter{g: g, inner: w} }

type gaugeWriter struct {
	g     *gauge
	inner dns.Writer
}

func (w *gaugeWriter) Write(p []byte) (int, error) {
	c := w.g.cur.Add(1)
	for {
		m := w.g.max.Load()
		if c <= m || w.g.max.CompareAndSwap(m, c) {
			break
		}
	}
	defer w.g.cur.Add(-1)
	n, err := w.inner.Write(p)
	if err == nil {
		w.g.done.Add(1)
	}
	return n, err
}

// ---- real miekg/dns UDP server -------------------------------------------

type backlogServer struct {
	conn     *net.UDPConn
	addr     *net.UDPAddr
	srv      *dns.Server
	entered  atomic.Int64 // handlers started (datagrams read and dispatched)
	returned atomic.Int64 // handlers finished
	serveErr chan error
}

// startBacklogServer runs dns.Server on a loopback UDPConn with the given
// writer decorator and handler, as dnsserver.ServePacket does. The handler is
// wrapped to count entries and returns.
func startBacklogServer(t *testing.T, dw dns.DecorateWriter, handle func(dns.ResponseWriter, *dns.Msg)) *backlogServer {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadBuffer(8 << 20) // best effort; pacing keeps the kernel queue short anyway
	bs := &backlogServer{conn: conn, addr: conn.LocalAddr().(*net.UDPAddr), serveErr: make(chan error, 1)}
	started := make(chan struct{})
	bs.srv = &dns.Server{
		PacketConn:        conn,
		Net:               "udp",
		DecorateWriter:    dw,
		NotifyStartedFunc: func() { close(started) },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			bs.entered.Add(1)
			defer bs.returned.Add(1)
			handle(w, r)
		}),
	}
	go func() { bs.serveErr <- bs.srv.ActivateAndServe() }()
	select {
	case <-started:
	case err := <-bs.serveErr:
		t.Fatalf("server failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	// Registered first, so it runs after every release registered later:
	// Shutdown waits for in-flight handlers.
	t.Cleanup(func() { _ = bs.srv.Shutdown() })
	return bs
}

func replyHandler(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	_ = w.WriteMsg(m) // write errors are irrelevant to the pile-up
}

// send writes n queries from one client socket, pacing in batches: after each
// batch it waits until the server has read it, so the kernel receive queue
// never drops datagrams and `entered` is exactly the number sent.
func (bs *backlogServer) send(t *testing.T, n int) {
	t.Helper()
	c, err := net.DialUDP("udp", nil, bs.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := new(dns.Msg)
	q.SetQuestion("example.org.", dns.TypeA)
	pkt, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	base := bs.entered.Load()
	for sent := 0; sent < n; {
		batch := min(backlogBatch, n-sent)
		for range batch {
			for try := 0; ; try++ {
				if _, err := c.Write(pkt); err == nil {
					break
				} else if try > 200 {
					t.Fatalf("client write: %v", err)
				}
				time.Sleep(time.Millisecond) // ENOBUFS: let the stack drain
			}
		}
		sent += batch
		waitFor(t, fmt.Sprintf("server to read %d datagrams", sent), func() bool {
			return bs.entered.Load()-base >= int64(sent)
		})
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(backlogWaitTO)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ---- memory and goroutine measurement ------------------------------------

// goInUse is Go-managed memory that is live or still reachable after a GC:
// heap plus goroutine stacks. This, not RSS, is what shows whether objects are
// still held.
func goInUse() uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapInuse + ms.StackInuse
}

// rssKiB reads this process's resident set size, or -1 if unavailable.
func rssKiB() int64 {
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		return -1
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return -1
	}
	return v
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }

// ---- goroutine profile grouping ------------------------------------------

// stackGroup is one line group of a debug=1 goroutine profile: count
// goroutines sharing the same stack, top frame first.
type stackGroup struct {
	count  int
	frames []string
}

// parseGoroutineProfile parses pprof's debug=1 goroutine text.
func parseGoroutineProfile(dump string) []stackGroup {
	var groups []stackGroup
	for block := range strings.SplitSeq(dump, "\n\n") {
		var g stackGroup
		for _, line := range strings.Split(block, "\n") {
			switch {
			case strings.Contains(line, " @ ") && g.count == 0:
				if n, err := strconv.Atoi(strings.Fields(line)[0]); err == nil {
					g.count = n
				}
			case strings.HasPrefix(line, "#"):
				// pprof pads columns with a variable number of tabs, so split
				// on any whitespace: "#", address, function+offset, file:line.
				f := strings.Fields(line)
				if len(f) >= 3 {
					fn := f[2]
					if i := strings.LastIndex(fn, "+0x"); i > 0 {
						fn = fn[:i]
					}
					g.frames = append(g.frames, fn)
				}
			}
		}
		if g.count > 0 && len(g.frames) > 0 {
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].count > groups[j].count })
	return groups
}

const (
	familyUDPWriteWait  = "udp-write-wait" // parked in the fd write lock under the DNS library's response writer
	familyUpstreamWait  = "upstream-wait"  // parked waiting on an upstream (proxy) read
	familyOther         = "other"
	frameFDWriteLock    = "internal/poll.(*fdMutex).rwlock"
	frameDNSResponseWr  = "github.com/miekg/dns.(*response).Write"
	frameServeUDPPacket = "github.com/miekg/dns.(*Server).serveUDPPacket"
	frameProxyLookup    = "plugin/pkg/proxy.(*Proxy).lookupDNS"
)

func hasFrame(g stackGroup, sub string) bool {
	for _, f := range g.frames {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

// classify names a group's stack family by its blocking frame and nearest
// caller: the task's "first blocking frame and nearest caller" grouping.
func classify(g stackGroup) string {
	switch {
	case hasFrame(g, frameProxyLookup):
		return familyUpstreamWait
	case hasFrame(g, frameFDWriteLock) && hasFrame(g, frameDNSResponseWr):
		return familyUDPWriteWait
	default:
		return familyOther
	}
}

// familyCounts totals goroutines per family.
func familyCounts(groups []stackGroup) map[string]int {
	out := map[string]int{}
	for _, g := range groups {
		out[classify(g)] += g.count
	}
	return out
}

func goroutineGroups(t *testing.T) []stackGroup {
	t.Helper()
	var buf bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		t.Fatal(err)
	}
	return parseGoroutineProfile(buf.String())
}

// quiesce returns the goroutine count once it has been stable for ~100ms, so a
// baseline is not skewed by goroutines from an earlier test still exiting.
func quiesce() int {
	deadline := time.Now().Add(10 * time.Second)
	last, stable := -1, 0
	for stable < 5 && time.Now().Before(deadline) {
		if n := runtime.NumGoroutine(); n == last {
			stable++
		} else {
			last, stable = n, 0
		}
		time.Sleep(20 * time.Millisecond)
	}
	return last
}

// settleGoroutines waits for the goroutine count to fall to at most want.
func settleGoroutines(t *testing.T, want int) {
	t.Helper()
	waitFor(t, fmt.Sprintf("goroutines to fall to <= %d (now %d)", want, runtime.NumGoroutine()), func() bool {
		return runtime.NumGoroutine() <= want
	})
}

// ---- tests ----------------------------------------------------------------

// TestUnshedWritersPileUpOnStalledSocket is the finding's mechanism end to
// end: with one write stalled on the listener's fd and no decorator, every
// datagram's handler goroutine finishes its work, then parks in the fd write
// wait queue holding its request and response; goroutines and memory grow
// linearly. Releasing the stall drains them and the memory becomes collectible.
func TestUnshedWritersPileUpOnStalledSocket(t *testing.T) {
	n := backlogDatagrams()
	g := new(gauge)
	bs := startBacklogServer(t, g.wrap, replyHandler)

	release := holdWriteLock(t, bs.conn)
	gBase, memBase, rssBase := quiesce(), goInUse(), rssKiB()

	bs.send(t, n)
	waitFor(t, "all handlers to reach the downstream write", func() bool { return g.cur.Load() >= int64(n) })

	gPeak := runtime.NumGoroutine()
	memPeak, rssPeak := goInUse(), rssKiB()
	groups := goroutineGroups(t)
	fams := familyCounts(groups)

	if got := bs.entered.Load(); got != int64(n) {
		t.Fatalf("handlers entered = %d, want %d", got, n)
	}
	if got := bs.returned.Load(); got != 0 {
		t.Errorf("handlers returned = %d while the write lock is held, want 0", got)
	}
	// Slack of 16 covers unrelated goroutines (runtime, earlier tests) that
	// exit between the baseline and the peak; the exact per-request evidence is
	// the stack-family count and the downstream-write gauge below.
	if grew := gPeak - gBase; grew < n-16 {
		t.Errorf("goroutines grew by %d, want ~%d (one per stalled datagram)", grew, n)
	}
	if got := g.max.Load(); got < int64(n) {
		t.Errorf("max concurrent downstream writes = %d, want %d", got, n)
	}
	if fams[familyUDPWriteWait] < n {
		t.Errorf("%s goroutines = %d, want >= %d; families: %v", familyUDPWriteWait, fams[familyUDPWriteWait], n, fams)
	}
	top := groups[0]
	if classify(top) != familyUDPWriteWait || !hasFrame(top, frameServeUDPPacket) {
		t.Errorf("dominant stack is not the UDP write-wait family rooted at serveUDPPacket (%d goroutines):\n%s",
			top.count, strings.Join(top.frames, "\n"))
	}
	perReq := (memPeak - memBase) / uint64(n)
	if perReq < 1024 {
		t.Errorf("retained %d B per stalled request, want >= 1 KiB (goroutine stack + request state)", perReq)
	}

	release()
	waitFor(t, "every handler to return after release", func() bool { return bs.returned.Load() == int64(n) })
	settleGoroutines(t, gBase)
	memAfter := goInUse()
	debug.FreeOSMemory()
	rssAfter := rssKiB()
	// Written without subtraction: memAfter can sit below memBase when earlier
	// iterations left garbage in the baseline, and uint64 would wrap.
	if memAfter > memBase+(memPeak-memBase)/4 {
		t.Errorf("Go-managed memory after release %.1f MiB, peak %.1f MiB, base %.1f MiB: not collectible",
			mib(memAfter), mib(memPeak), mib(memBase))
	}

	t.Logf("EVIDENCE unshed N=%d goroutines base=%d peak=%d (+%d) handlers entered=%d returned-while-stalled=0 "+
		"max-concurrent-downstream-writes=%d goroutine-families=%v",
		n, gBase, gPeak, gPeak-gBase, n, g.max.Load(), fams)
	t.Logf("EVIDENCE unshed memory (heap+stack in use after GC): base=%.1fMiB peak=%.1fMiB after-release=%.1fMiB => %d B/stalled request; "+
		"RSS KiB base=%d peak=%d after-release+FreeOSMemory=%d",
		mib(memBase), mib(memPeak), mib(memAfter), perReq, rssBase, rssPeak, rssAfter)
	t.Logf("EVIDENCE unshed dominant stack (%d goroutines), top frame first:\n  %s", top.count, strings.Join(top.frames, "\n  "))
}

// TestShedBoundsWritersOnStalledSocket runs the identical stall with the
// plugin installed through the production path: decorateWriterFactory for the
// writer and Shed.ServeDNS for the handler. One writer goroutine takes the
// stall; the queue stays within stackDepth; handlers return; drops are counted.
func TestShedBoundsWritersOnStalledSocket(t *testing.T) {
	n := backlogDatagrams()
	s := newShed(t, answering())
	srv := &dnsserver.Server{}
	g := new(gauge)
	dec := s.decorateWriterFactory(srv)
	st := func() *socketState { v, _ := registry.Load(srv); return v.(*socketState) }()

	dropResp := droppedTotal.WithLabelValues(srv.Address(), "response")
	dropQuery := droppedTotal.WithLabelValues(srv.Address(), "query")
	respBefore, queryBefore := testutil.ToFloat64(dropResp), testutil.ToFloat64(dropQuery)

	bs := startBacklogServer(t, func(w dns.Writer) dns.Writer { return dec(g.wrap(w)) },
		func(w dns.ResponseWriter, r *dns.Msg) {
			ctx := context.WithValue(context.Background(), dnsserver.Key{}, srv)
			_, _ = s.ServeDNS(ctx, w, r)
		})
	release := holdWriteLock(t, bs.conn)
	gBase, memBase := quiesce(), goInUse()

	// Send in batches and sample the queue depth: it must never exceed the bound.
	var maxDepth atomic.Int64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			if d := st.stack.n.Load(); d > maxDepth.Load() {
				maxDepth.Store(d)
			}
			select {
			case <-stop:
				return
			default:
				runtime.Gosched()
			}
		}
	}()
	bs.send(t, n)
	waitFor(t, "every handler to return while the write is still stalled", func() bool {
		return bs.returned.Load() == int64(n)
	})
	close(stop)
	<-sampled

	gPeak, memPeak := runtime.NumGoroutine(), goInUse()
	groups := goroutineGroups(t)
	fams := familyCounts(groups)
	depthAtStall := st.stack.n.Load()

	if grew := gPeak - gBase; grew > 16 {
		t.Errorf("goroutines grew by %d during the stall, want a small constant (handlers must not pile up)", grew)
	}
	if got := g.max.Load(); got != 1 {
		t.Errorf("max concurrent downstream writes = %d, want 1 (one writer per socket)", got)
	}
	if got := maxDepth.Load(); got > stackDepth {
		t.Errorf("queue depth reached %d, bound is %d", got, stackDepth)
	}
	if depthAtStall != stackDepth {
		t.Errorf("queue depth at stall = %d, want a full stack of %d", depthAtStall, stackDepth)
	}
	if fams[familyUDPWriteWait] > 1 {
		t.Errorf("%d goroutines parked in the fd write wait, want <= 1 (the single writer)", fams[familyUDPWriteWait])
	}

	release()
	// The writer drains whatever is still queued; every query is then either
	// written, dropped as a response, or dropped as a query before the chain.
	waitFor(t, "stack to drain after release", func() bool { return st.stack.n.Load() == 0 && g.cur.Load() == 0 })
	if err := s.shutdown(); err != nil {
		t.Fatal(err)
	}
	respDropped := int64(testutil.ToFloat64(dropResp) - respBefore)
	queryDropped := int64(testutil.ToFloat64(dropQuery) - queryBefore)
	written := g.done.Load()
	if total := written + respDropped + queryDropped; total != int64(n) {
		t.Errorf("accounting: written=%d + response-drops=%d + query-drops=%d = %d, want %d", written, respDropped, queryDropped, total, n)
	}
	if written > stackDepth+1 {
		t.Errorf("wrote %d responses through a stalled socket, at most %d (queue + the write in progress) can survive", written, stackDepth+1)
	}
	settleGoroutines(t, gBase-1) // the plugin's writer goroutine exits at shutdown

	t.Logf("EVIDENCE shed N=%d goroutines base=%d peak=%d (+%d) max-concurrent-downstream-writes=%d queue-depth max=%d bound=%d "+
		"written=%d response-drops=%d query-drops=%d goroutine-families=%v memory(heap+stack) base=%.1fMiB peak=%.1fMiB",
		n, gBase, gPeak, gPeak-gBase, g.max.Load(), maxDepth.Load(), stackDepth,
		written, respDropped, queryDropped, fams, mib(memBase), mib(memPeak))
}

// TestStalledWriteControls: the finding applies only to a stalled write path.
func TestStalledWriteControls(t *testing.T) {
	t.Run("fast writer, no stall: no pile-up", func(t *testing.T) {
		n := backlogDatagrams()
		g := new(gauge)
		bs := startBacklogServer(t, g.wrap, replyHandler)
		gBase := quiesce()
		bs.send(t, n)
		waitFor(t, "every handler to return with nothing held", func() bool { return bs.returned.Load() == int64(n) })
		settleGoroutines(t, gBase)
		// The peak is an observation, not an assertion: the sender paces on
		// datagrams read, not on handlers finished, so the serialized write
		// drain can lag dispatch even with no stall. What distinguishes a
		// healthy socket is that nothing stays parked once the burst is over.
		t.Logf("EVIDENCE control fast-writer N=%d all handlers returned without a release; goroutines settled at base=%d; "+
			"transient max-concurrent-downstream-writes=%d (sender burst=%d datagrams per read-pacing step)",
			n, gBase, g.max.Load(), backlogBatch)
	})

	t.Run("one writer per installed decorator, bounded per socket", func(t *testing.T) {
		const sockets = 3
		s := newShed(t, nil)
		type sock struct {
			dec dns.DecorateWriter
			st  *socketState
			bw  *blockingWriter
			g   *gauge
		}
		socks := make([]sock, sockets)
		for i := range socks {
			srv := &dnsserver.Server{}
			socks[i].dec = s.decorateWriterFactory(srv)
			v, _ := registry.Load(srv)
			socks[i].st = v.(*socketState)
			socks[i].bw = &blockingWriter{entered: make(chan struct{}, stackDepth+4), release: make(chan struct{})}
			socks[i].g = new(gauge)
			bw := socks[i].bw
			t.Cleanup(func() { close(bw.release) })
		}
		data := packedReply(t)
		for _, sk := range socks {
			// Many concurrent handler writes into one socket's decorator.
			var wg sync.WaitGroup
			for range 4 * stackDepth {
				wg.Go(func() { _, _ = sk.dec(sk.g.wrap(sk.bw)).Write(data) })
			}
			wg.Wait()
		}
		for i, sk := range socks {
			<-sk.bw.entered // that socket's writer is parked in its downstream write
			waitFor(t, fmt.Sprintf("socket %d to fill", i), func() bool { return sk.st.stack.full() })
			if got := sk.g.max.Load(); got != 1 {
				t.Errorf("socket %d: max concurrent downstream writes = %d, want 1", i, got)
			}
			if got := sk.st.stack.n.Load(); got > stackDepth {
				t.Errorf("socket %d: queue depth %d exceeds bound %d", i, got, stackDepth)
			}
		}
		var inProgress int64
		for _, sk := range socks {
			inProgress += sk.g.cur.Load()
		}
		if inProgress != sockets {
			t.Errorf("downstream writes in progress across %d sockets = %d, want %d (one each)", sockets, inProgress, sockets)
		}
		t.Logf("EVIDENCE control multi-socket sockets=%d writes-in-progress=%d (one per decorator) each queue<=%d", sockets, inProgress, stackDepth)
	})
}

// TestStalledWriteStackFamily checks the classifier that tells the pile-up's
// stack family apart from an upstream-bound surge, using a synthetic profile.
func TestStalledWriteStackFamily(t *testing.T) {
	const dump = `goroutine profile: total 1830
1000 @ 0x1 0x2 0x3
#	0x1	internal/poll.runtime_Semacquire+0x2c	/go/src/internal/poll/fd_mutex.go:99
#	0x2	internal/poll.(*fdMutex).rwlock+0x118	/go/src/internal/poll/fd_mutex.go:147
#	0x3	internal/poll.(*FD).writeLock+0x10	/go/src/internal/poll/fd_mutex.go:239
#	0x4	internal/poll.(*FD).WriteMsg+0x20	/go/src/internal/poll/fd_unix.go:517
#	0x5	net.(*UDPConn).WriteMsgUDP+0x30	/go/src/net/udpsock.go:244
#	0x6	github.com/miekg/dns.WriteToSessionUDP+0x40	/dns/udp.go:53
#	0x7	github.com/miekg/dns.(*response).Write+0x50	/dns/server.go:780
#	0x8	github.com/miekg/dns.(*response).WriteMsg+0x60	/dns/server.go:766
#	0x9	github.com/miekg/dns.(*Server).serveUDPPacket+0x70	/dns/server.go:556

800 @ 0x10 0x11 0x12
#	0x10		internal/poll.runtime_pollWait+0x20				/go/src/internal/poll/fd_poll_runtime.go:84
#	0x11	internal/poll.(*FD).Read+0x30	/go/src/internal/poll/fd_unix.go:165
#	0x12	net.(*conn).Read+0x40	/go/src/net/net.go:194
#	0x13	github.com/miekg/dns.(*Conn).ReadMsg+0x50	/dns/client.go:200
#	0x14		github.com/coredns/coredns/plugin/pkg/proxy.(*Proxy).lookupDNS+0x60		/coredns/plugin/pkg/proxy/connect.go:206
#	0x15	github.com/coredns/coredns/plugin/pkg/proxy.(*Proxy).Connect+0x70	/coredns/plugin/pkg/proxy/connect.go:320

30 @ 0x20 0x21
#	0x20	runtime.gopark+0x10	/go/src/runtime/proc.go:460
#	0x21	runtime.selectgo+0x20	/go/src/runtime/select.go:335
`
	groups := parseGoroutineProfile(dump)
	if len(groups) != 3 {
		t.Fatalf("parsed %d groups, want 3", len(groups))
	}
	if groups[0].count != 1000 || groups[0].frames[0] != "internal/poll.runtime_Semacquire" {
		t.Errorf("top group = %d @ %q, want 1000 @ internal/poll.runtime_Semacquire", groups[0].count, groups[0].frames[0])
	}
	want := map[string]int{familyUDPWriteWait: 1000, familyUpstreamWait: 800, familyOther: 30}
	got := familyCounts(groups)
	for fam, n := range want {
		if got[fam] != n {
			t.Errorf("family %q = %d, want %d (all: %v)", fam, got[fam], n, got)
		}
	}
	if !hasFrame(groups[0], frameServeUDPPacket) {
		t.Error("write-wait group should be rooted at serveUDPPacket, not ServePacket (which runs on the single reader goroutine)")
	}
}
