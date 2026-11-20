package test

// End-to-end reproduction for finding 05: UDP PROXY session cache workers across
// in-process reloads of a real CoreDNS instance (caddy Restart).
//
// A "worker" is a goroutine rooted at expirable.NewLRU from the pinned
// golang-lru/v2 v2.0.7. In this repository the only user of that package is the
// proxyproto session cache, so each worker is one session cache that has been
// created by the first tracked session on one PacketConn wrapper.
//
// The assertions describe behaviour observed today. Where a fix is expected to
// change a number, the comment says so.

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"

	"github.com/miekg/dns"
	proxyproto "github.com/pires/go-proxyproto"
)

func lruWorkerCount() int {
	var buf bytes.Buffer
	pprof.Lookup("goroutine").WriteTo(&buf, 2)
	n := 0
	for rec := range strings.SplitSeq(buf.String(), "\n\n") {
		if strings.Contains(rec, "golang-lru/v2/expirable.NewLRU") {
			n++
		}
	}
	return n
}

// packetConnOf returns the dynamic type and address of the packet connection
// caddy holds for server k, and whether caddy could hand it to a new instance
// on reload (that requires a File() method; see caddy.Restart).
func packetConnOf(t *testing.T, inst *caddy.Instance, k int) (typ string, ptr uintptr, reusable bool) {
	t.Helper()
	srvs := inst.Servers()
	if len(srvs) <= k {
		t.Fatalf("instance has %d servers, want index %d", len(srvs), k)
	}
	f := reflect.ValueOf(srvs[k]).FieldByName("packet")
	if !f.IsValid() || f.IsNil() {
		t.Fatal("server has no packet conn")
	}
	e := f.Elem()
	reusable = e.Type().Implements(reflect.TypeOf((*caddy.PacketConn)(nil)).Elem())
	return e.Type().String(), e.Pointer(), reusable
}

// sendTracked sends one PPv2 (UDP/IPv4) datagram carrying a DNS query from a
// fresh client socket and checks the answer comes back.
func sendTracked(t *testing.T, serverPort int, realClient string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("whoami.example.org.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	src := &net.UDPAddr{IP: net.ParseIP(realClient), Port: 40000}
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.UDPv4,
		SourceAddr:        src,
		DestinationAddr:   &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 53},
	}
	hdr, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: serverPort})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var lastErr error
	for range 3 { // UDP on CI can drop; retry
		conn.Write(append(append([]byte{}, hdr...), wire...))
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, err := conn.Read(buf)
		if err != nil {
			lastErr = err
			continue
		}
		r := new(dns.Msg)
		if err := r.Unpack(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %s", dns.RcodeToString[r.Rcode])
		}
		return
	}
	t.Fatalf("no reply to tracked query: %v", lastErr)
}

func TestProxyProtoUDPSessionWorkersAcrossReloads(t *testing.T) {
	const reloads = 5
	port := pickPort(t)
	corefile := fmt.Sprintf(`.:%d {
		bind 127.0.0.1
		proxyproto {
			udp_session_tracking 2s
		}
		whoami
	}`, port)

	settle := func() {
		for range 3 {
			runtime.GC()
			time.Sleep(20 * time.Millisecond)
		}
	}
	base := lruWorkerCount()
	delta := func() int { return lruWorkerCount() - base }

	c, err := CoreDNSServer(corefile)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			c.Stop()
		}
	}()

	typ, prev, reusable := packetConnOf(t, c, 0)
	t.Logf("packet conn type=%s reusable-by-caddy-on-reload=%v", typ, reusable)
	if !strings.HasSuffix(typ, "proxyproto.PacketConn") {
		t.Fatalf("expected the proxyproto wrapper, got %s", typ)
	}
	if reusable {
		t.Fatal("wrapper has File(); caddy would reuse it and a reload would not replace it")
	}

	// Lazy start: a listener that has served no tracked session has no worker.
	if d := delta(); d != 0 {
		t.Fatalf("workers before any traffic = +%d, want +0", d)
	}
	sendTracked(t, port, "198.51.100.1")
	if d := delta(); d != 1 {
		t.Fatalf("workers after first tracked session = +%d, want +1", d)
	}

	for i := 1; i <= reloads; i++ {
		c, err = c.Restart(NewInput(corefile))
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		_, cur, _ := packetConnOf(t, c, 0)
		if cur == prev {
			t.Fatalf("reload %d kept the same packet conn object", i)
		}
		prev = cur

		// Old listener is closed, new one has served nothing yet: still i workers
		// (all belonging to closed listeners); expected 0 after a fix.
		if d := delta(); d != i {
			t.Fatalf("after reload %d, before traffic: workers=+%d, want +%d", i, d, i)
		}
		sendTracked(t, port, fmt.Sprintf("198.51.100.%d", i+1))
		if d := delta(); d != i+1 {
			t.Fatalf("after reload %d + traffic: workers=+%d, want +%d", i, d, i+1)
		}
		t.Logf("reload %d: 1 live listener, %d session-cache workers (%d belong to closed listeners)", i, delta(), delta()-1)
	}

	// A reload with no traffic afterwards adds nothing (lazy), but retains all.
	c, err = c.Restart(NewInput(corefile))
	if err != nil {
		t.Fatal(err)
	}
	if d := delta(); d != reloads+1 {
		t.Fatalf("after idle reload: workers=+%d, want +%d", d, reloads+1)
	}

	// Waiting past the session TTL expires entries but not workers.
	time.Sleep(3 * 2 * time.Second)
	settle()
	if d := delta(); d != reloads+1 {
		t.Fatalf("after 3xTTL: workers=+%d, want +%d", d, reloads+1)
	}

	c.Stop()
	stopped = true
	settle()
	if d := delta(); d != reloads+1 {
		t.Fatalf("after final Stop: workers=+%d, want +%d (expected +0 after a fix)", d, reloads+1)
	}
	t.Logf("after final Stop with NO live listener: %d session-cache workers remain", delta())
}

// Controls: reloads of listeners that are not eligible create no workers.
func TestProxyProtoUDPSessionWorkersControls(t *testing.T) {
	tests := []struct {
		name     string
		block    string
		tracked  bool // send PPv2 traffic
		wantPlus int
	}{
		{"no proxyproto plugin", "", false, 0},
		{"proxyproto without udp_session_tracking", "proxyproto", true, 0},
		{"tracking enabled, no traffic", "proxyproto {\n udp_session_tracking 2s\n}", false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := pickPort(t)
			corefile := fmt.Sprintf(".:%d {\n bind 127.0.0.1\n %s\n whoami\n}", port, tc.block)
			base := lruWorkerCount()
			c, err := CoreDNSServer(corefile)
			if err != nil {
				t.Fatal(err)
			}
			for range 3 {
				if tc.tracked {
					sendTracked(t, port, "198.51.100.1")
				}
				if c, err = c.Restart(NewInput(corefile)); err != nil {
					t.Fatal(err)
				}
			}
			c.Stop()
			time.Sleep(50 * time.Millisecond)
			if got := lruWorkerCount() - base; got != tc.wantPlus {
				t.Fatalf("workers=+%d, want +%d", got, tc.wantPlus)
			}
		})
	}
}
