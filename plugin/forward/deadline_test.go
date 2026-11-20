//go:build linux || darwin

package forward

import (
	"bytes"
	"context"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// Reproduction for finding 02: does one forwarded request stay in
// Forward.ServeDNS longer than the 5s retry window (defaultTimeout) or an
// earlier caller deadline? The window is shrunk for most tests so they stay
// fast. Each test asserts the desired behavior (the request must not outlive
// its budget); a failure is evidence of the gap.

const deadlineGrace = 250 * time.Millisecond

// silentUDP is a UDP upstream that counts queries and never answers.
func silentUDP(t *testing.T) (addr string, queries func() int) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	ch := make(chan struct{}, 64)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			ch <- struct{}{}
		}
	}()
	return pc.LocalAddr().String(), func() int { return len(ch) }
}

// blackholeTCP returns the address of a TCP listener whose accept queue is
// full, so further SYNs are dropped and a connect hangs. This is how an
// unreachable or filtered upstream looks to the dialer.
func blackholeTCP(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skipf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Skipf("getsockname: %v", err)
	}
	addr := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sa.(*syscall.SockaddrInet4).Port}).String()

	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for range 32 {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			break
		}
		held = append(held, c)
	}
	// Probe: the blackhole only counts if a dial really hangs.
	if hangs(addr) {
		return addr
	}
	// macOS completes loopback handshakes regardless of the backlog. Fall back to
	// an RFC 5737 documentation address, which is unroutable and normally dropped.
	if hangs(testNetAddr) {
		return testNetAddr
	}
	t.Skip("no blackholed TCP address available on this host")
	return ""
}

const testNetAddr = "192.0.2.1:53"

func hangs(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		c.Close()
		return false
	}
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func newDeadlineForward(readTimeout time.Duration, forceTCP bool, addrs ...string) *Forward {
	f := New()
	f.maxfails = 0 // no health checks, no marking upstreams down: one variable at a time
	f.opts.ForceTCP = forceTCP
	for _, a := range addrs {
		p := proxy.NewProxy("forward", a, transport.DNS)
		p.SetReadTimeout(readTimeout)
		f.proxies = append(f.proxies, p)
	}
	return f
}

func setWindow(t *testing.T, d time.Duration) {
	t.Helper()
	orig := defaultTimeout
	defaultTimeout = d
	t.Cleanup(func() { defaultTimeout = orig })
}

func serve(t *testing.T, f *Forward, ctx context.Context, tcp bool) (rcode int, err error, elapsed time.Duration, id [2]uint16) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	id[0] = m.Id
	rec := &test.ResponseWriter{TCP: tcp}
	start := time.Now()
	rcode, err = f.ServeDNS(ctx, rec, m)
	elapsed = time.Since(start)
	id[1] = m.Id
	return
}

// A retry that begins shortly before the window ends is given a full
// per-operation timeout instead of the time that is left.
func TestForwardRetryExceedsWindow(t *testing.T) {
	const window, readTimeout = 600 * time.Millisecond, 500 * time.Millisecond
	setWindow(t, window)
	a1, q1 := silentUDP(t)
	a2, q2 := silentUDP(t)
	f := newDeadlineForward(readTimeout, false, a1, a2)

	rcode, err, elapsed, id := serve(t, f, t.Context(), false)
	t.Logf("window=%v read_timeout=%v: attempts=%d (upstream1=%d upstream2=%d) elapsed=%v rcode=%s err=%v",
		window, readTimeout, q1()+q2(), q1(), q2(), elapsed.Round(time.Millisecond), dns.RcodeToString[rcode], err)

	if id[0] != id[1] {
		t.Errorf("query ID not restored: %d -> %d", id[0], id[1])
	}
	if rcode != dns.RcodeServerFailure || err == nil {
		t.Errorf("expected SERVFAIL with an error, got %s, %v", dns.RcodeToString[rcode], err)
	}
	if q1()+q2() < 2 {
		t.Errorf("expected a second attempt that starts inside the window, saw %d", q1()+q2())
	}
	if elapsed > window+deadlineGrace {
		t.Errorf("request stayed in ServeDNS for %v with a %v window; the retry started at ~%v and received a full %v read timeout instead of the ~%v left",
			elapsed.Round(time.Millisecond), window, readTimeout, readTimeout, window-readTimeout)
	}
}

// An earlier caller deadline (for example from the cancel plugin) does not
// interrupt an established UDP exchange.
func TestForwardCallerDeadlineOutlived(t *testing.T) {
	const caller, readTimeout = 150 * time.Millisecond, 500 * time.Millisecond
	a, q := silentUDP(t)
	f := newDeadlineForward(readTimeout, false, a)

	ctx, cancel := context.WithTimeout(t.Context(), caller)
	defer cancel()
	rcode, err, elapsed, _ := serve(t, f, ctx, false)
	t.Logf("caller deadline=%v read_timeout=%v: attempts=%d elapsed=%v rcode=%s err=%v ctx.Err=%v",
		caller, readTimeout, q(), elapsed.Round(time.Millisecond), dns.RcodeToString[rcode], err, ctx.Err())
	if elapsed > caller+deadlineGrace {
		t.Errorf("ServeDNS returned after %v, %v after the caller gave up at %v", elapsed.Round(time.Millisecond), (elapsed - caller).Round(time.Millisecond), caller)
	}
}

// Plain TCP dial: the dial only sees the caller's context, not the 5s window.
func TestForwardBlackholedTCPDial(t *testing.T) {
	const window = 500 * time.Millisecond
	setWindow(t, window)

	t.Run("no caller deadline", func(t *testing.T) {
		addr := blackholeTCP(t)
		f := newDeadlineForward(2*time.Second, true, addr)
		// The watchdog only bounds the test; the dial itself has a 30s timeout on a fresh transport.
		const watchdog = 3 * time.Second
		ctx, cancel := context.WithTimeout(t.Context(), watchdog)
		defer cancel()
		rcode, err, elapsed, _ := serve(t, f, ctx, true)
		t.Logf("window=%v force_tcp, blackholed upstream, no caller deadline: elapsed=%v (watchdog %v) rcode=%s err=%v",
			window, elapsed.Round(time.Millisecond), watchdog, dns.RcodeToString[rcode], err)
		if elapsed > window+deadlineGrace {
			t.Errorf("request stayed in the TCP dial for %v, %.0fx the %v window; only the %v watchdog ended it", elapsed.Round(time.Millisecond), float64(elapsed)/float64(window), window, watchdog)
		}
	})

	t.Run("caller deadline control", func(t *testing.T) {
		addr := blackholeTCP(t)
		f := newDeadlineForward(2*time.Second, true, addr)
		const caller = 300 * time.Millisecond
		ctx, cancel := context.WithTimeout(t.Context(), caller)
		defer cancel()
		_, err, elapsed, _ := serve(t, f, ctx, true)
		t.Logf("caller deadline=%v: elapsed=%v err=%v", caller, elapsed.Round(time.Millisecond), err)
		if elapsed > caller+deadlineGrace {
			t.Errorf("a caller deadline did not bound the plain TCP dial: %v", elapsed)
		}
	})
}

// Control: a prompt answer is returned and the query ID restored.
func TestForwardPromptAnswerControl(t *testing.T) {
	s := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{test.A("example.org. 60 IN A 192.0.2.53")}
		w.WriteMsg(resp)
	})
	t.Cleanup(s.Close)
	f := newDeadlineForward(time.Second, false, s.Addr)
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	originalID := m.Id
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	start := time.Now()
	rcode, err := f.ServeDNS(t.Context(), rec, m)
	if err != nil || rcode != 0 {
		t.Fatalf("rcode=%d err=%v", rcode, err)
	}
	if m.Id != originalID || rec.Msg == nil || rec.Msg.Id != originalID || len(rec.Msg.Answer) != 1 {
		t.Fatalf("bad answer or ID: request ID %d, reply %v", m.Id, rec.Msg)
	}
	t.Logf("prompt answer in %v, ID restored", time.Since(start).Round(time.Millisecond))
}

// Full-size run with the shipped defaults (5s window, 2s read timeout, fresh
// transports). Opt-in because it takes up to ~40s:
//
//	COREDNS_SLOW_DEADLINE_TESTS=1 go test ./plugin/forward -run TestForwardDefaultsFullScale -v
func TestForwardDefaultsFullScale(t *testing.T) {
	if os.Getenv("COREDNS_SLOW_DEADLINE_TESTS") == "" {
		t.Skip("set COREDNS_SLOW_DEADLINE_TESTS=1 to run")
	}
	t.Run("two silent UDP upstreams", func(t *testing.T) {
		a1, q1 := silentUDP(t)
		a2, q2 := silentUDP(t)
		f := newDeadlineForward(2*time.Second, false, a1, a2) // 2s is the default read_timeout
		rcode, err, elapsed, _ := serve(t, f, t.Context(), false)
		t.Logf("defaults, UDP: attempts=%d elapsed=%v rcode=%s err=%v", q1()+q2(), elapsed.Round(10*time.Millisecond), dns.RcodeToString[rcode], err)
		if elapsed > 5*time.Second+deadlineGrace {
			t.Errorf("request stayed %v against a 5s window", elapsed.Round(10*time.Millisecond))
		}
	})
	t.Run("blackholed TCP upstream, fresh transport", func(t *testing.T) {
		addr := blackholeTCP(t)
		f := newDeadlineForward(2*time.Second, true, addr)
		rcode, err, elapsed, _ := serve(t, f, t.Context(), true)
		t.Logf("defaults, force_tcp blackhole: elapsed=%v rcode=%s err=%v", elapsed.Round(10*time.Millisecond), dns.RcodeToString[rcode], err)
		if elapsed > 5*time.Second+deadlineGrace {
			t.Errorf("request stayed %v against a 5s window", elapsed.Round(10*time.Millisecond))
		}
	})
}

// stacksContaining counts goroutines whose stack mentions marker.
func stacksContaining(marker string) int {
	var buf bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&buf, 2)
	n := 0
	for _, g := range strings.Split(buf.String(), "\n\n") {
		if strings.Contains(g, marker) {
			n++
		}
	}
	return n
}

// Many callers give up (caller deadline) while the upstream is silent or
// blackholed. Count requests still inside ServeDNS, and the goroutine stacks
// in the upstream read / dial, after the callers have gone. This is the
// "live request buildup" the finding describes; it is transient.
func TestForwardInFlightAfterCallersGiveUp(t *testing.T) {
	const n = 100
	const caller = 150 * time.Millisecond

	run := func(t *testing.T, f *Forward, tcp bool, marker string, sampleAt, releaseAfter time.Duration) {
		var inflight atomic.Int64
		var wg sync.WaitGroup
		// The watchdog only bounds the test; it ends anything still pending at releaseAfter.
		watchdog, cancelWatchdog := context.WithCancel(t.Context())
		defer cancelWatchdog()
		time.AfterFunc(releaseAfter, cancelWatchdog)
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Each caller gives up after `caller`.
				ctx, cancel := context.WithTimeout(watchdog, caller)
				defer cancel()
				inflight.Add(1)
				defer inflight.Add(-1)
				m := new(dns.Msg)
				m.SetQuestion("example.org.", dns.TypeA)
				f.ServeDNS(ctx, &test.ResponseWriter{TCP: tcp}, m)
			}()
		}
		time.Sleep(sampleAt)
		during, stacks := inflight.Load(), stacksContaining(marker)
		wg.Wait()
		t.Logf("callers gave up at %v; at %v: %d of %d requests still in ServeDNS, %d goroutine stacks in %q; all returned by %v",
			caller, sampleAt, during, n, stacks, marker, releaseAfter)
		if during != 0 {
			t.Errorf("%d requests were still in ServeDNS %v after their callers gave up at %v", during, sampleAt-caller, caller)
		}
	}

	t.Run("silent UDP upstream, established read", func(t *testing.T) {
		a, _ := silentUDP(t)
		f := newDeadlineForward(800*time.Millisecond, false, a)
		run(t, f, false, "proxy.(*Proxy).lookupDNS", 400*time.Millisecond, 3*time.Second)
	})
	t.Run("blackholed TCP upstream, dial", func(t *testing.T) {
		a := blackholeTCP(t)
		f := newDeadlineForward(2*time.Second, true, a)
		// The dial honors the caller context, so this is expected to drain: control case.
		run(t, f, true, "proxy.(*Transport).dial", 400*time.Millisecond, 3*time.Second)
	})
}
