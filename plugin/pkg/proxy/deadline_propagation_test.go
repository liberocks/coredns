package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// These tests record how an *established* upstream exchange (UDP, TCP, DoT)
// reacts to an earlier caller deadline or cancellation. They assert the
// desired behavior: the exchange must not outlive the caller. Failures are
// evidence of the deadline-propagation gap described in finding 02.

const (
	// upstreamReadTimeout is the per-operation read timeout configured on the
	// proxy (the equivalent of the forward `read_timeout` option).
	upstreamReadTimeout = time.Second
	// callerBudget is the caller's deadline; it is far shorter than upstreamReadTimeout.
	callerBudget = 150 * time.Millisecond
	// grace is the scheduling slack allowed on top of the caller's deadline.
	grace = 250 * time.Millisecond
)

// silentUpstream accepts DNS queries over proto and never answers until released.
type silentUpstream struct {
	addr    string
	queries chan struct{}
	release chan struct{}
}

func newSilentUpstream(t *testing.T, proto string) *silentUpstream {
	t.Helper()
	u := &silentUpstream{queries: make(chan struct{}, 16), release: make(chan struct{})}
	// Cleanups run last-in-first-out: release the held exchanges before closing sockets.
	switch proto {
	case "udp":
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		t.Cleanup(func() { close(u.release) })
		u.addr = pc.LocalAddr().String()
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, _, err := pc.ReadFrom(buf); err != nil {
					return
				}
				u.queries <- struct{}{}
			}
		}()
	case "tcp", "tcp-tls":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if proto == "tcp-tls" {
			l = tls.NewListener(l, selfSignedTLS(t))
		}
		t.Cleanup(func() { l.Close() })
		t.Cleanup(func() { close(u.release) })
		u.addr = l.Addr().String()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					// Read the 2 byte length prefix and the query, then hold.
					var hdr [2]byte
					if _, err := io.ReadFull(c, hdr[:]); err != nil {
						return
					}
					body := make([]byte, int(hdr[0])<<8|int(hdr[1]))
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					u.queries <- struct{}{}
					<-u.release
				}()
			}
		}()
	}
	return u
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "deadline.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// TestEstablishedReadIgnoresCallerDeadline holds the upstream reply and checks
// whether Proxy.Connect returns when the caller's context ends, or only when
// the per-operation read timeout fires.
func TestEstablishedReadIgnoresCallerDeadline(t *testing.T) {
	for _, proto := range []string{"udp", "tcp", "tcp-tls"} {
		for _, how := range []string{"deadline", "cancel"} {
			t.Run(proto+"/"+how, func(t *testing.T) {
				up := newSilentUpstream(t, proto)

				p := NewProxy("forward", up.addr, transport.DNS)
				if proto == "tcp-tls" {
					p = NewProxy("forward", up.addr, transport.TLS)
					// The test server uses a throwaway certificate.
					p.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- test only
				}
				p.SetReadTimeout(upstreamReadTimeout)
				t.Cleanup(func() { p.transport.cleanup(true) })

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if how == "deadline" {
					ctx, cancel = context.WithTimeout(t.Context(), callerBudget)
					defer cancel()
				} else {
					time.AfterFunc(callerBudget, cancel)
				}

				msg := new(dns.Msg)
				msg.SetQuestion("example.org.", dns.TypeA)
				originalID := msg.Id
				state := request.Request{Req: msg, W: &test.ResponseWriter{TCP: proto != "udp"}}

				start := time.Now()
				_, _, _, err := p.Connect(ctx, state, Options{ForceTCP: proto != "udp"})
				elapsed := time.Since(start)

				select {
				case <-up.queries:
				default:
					t.Fatal("the upstream never received the query, so the established read was not exercised")
				}
				t.Logf("%s/%s: caller=%v read_timeout=%v elapsed=%v err=%v ctx.Err=%v",
					proto, how, callerBudget, upstreamReadTimeout, elapsed.Round(time.Millisecond), err, ctx.Err())

				if msg.Id != originalID {
					t.Errorf("request ID = %d, want %d", msg.Id, originalID)
				}
				if elapsed > callerBudget+grace {
					t.Errorf("Connect kept an established %s read pending for %v after the caller ended at %v (read_timeout %v)",
						proto, elapsed.Round(time.Millisecond), callerBudget, upstreamReadTimeout)
				}
			})
		}
	}
}

// TestPromptExchangeControl is the control: a prompt upstream answer is
// returned unchanged and the original query ID is restored.
func TestPromptExchangeControl(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		name := "udp"
		if tcp {
			name = "tcp"
		}
		t.Run(name, func(t *testing.T) {
			server := newAnsweringServer(t)
			p := NewProxy("forward", server, transport.DNS)
			t.Cleanup(func() { p.transport.cleanup(true) })

			ctx, cancel := context.WithTimeout(t.Context(), callerBudget*10)
			defer cancel()
			msg := new(dns.Msg)
			msg.SetQuestion("example.org.", dns.TypeA)
			originalID := msg.Id
			ret, _, _, err := p.Connect(ctx, request.Request{Req: msg, W: &test.ResponseWriter{TCP: tcp}}, Options{ForceTCP: tcp})
			if err != nil {
				t.Fatal(err)
			}
			if len(ret.Answer) != 1 || ret.Id != originalID || msg.Id != originalID {
				t.Fatalf("unexpected result: answers=%d ret.Id=%d msg.Id=%d want ID %d", len(ret.Answer), ret.Id, msg.Id, originalID)
			}
		})
	}
}

func newAnsweringServer(t *testing.T) string {
	t.Helper()
	// Serve UDP and TCP on the same port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Answer = []dns.RR{test.A("example.org. 60 IN A 192.0.2.53")}
		w.WriteMsg(resp)
	})
	udp := &dns.Server{PacketConn: pc, Handler: h}
	tcp := &dns.Server{Listener: l, Handler: h}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	t.Cleanup(func() { udp.Shutdown(); tcp.Shutdown() })
	// Wait for both servers to accept.
	for range 100 {
		c, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return l.Addr().String()
}

// TestPlainTCPDialTimeoutStates walks the adaptive plain TCP dial timeout
// through the states a transport can be in, using the same functions
// Transport.dial uses (dialTimeout / updateDialTimeout, which dial calls even
// when the dial failed). The dial timeout is compared with the 5s forwarding
// window; the dial itself only sees the caller's context, never that window.
func TestPlainTCPDialTimeoutStates(t *testing.T) {
	const forwardWindow = 5 * time.Second // forward.defaultTimeout

	fail := func(tr *Transport, n int) {
		for range n {
			tr.updateDialTimeout(tr.dialTimeout()) // a timed-out dial feeds its own duration back
		}
	}
	healthy := func(tr *Transport, n int) {
		for range n {
			tr.updateDialTimeout(time.Millisecond)
		}
	}

	for _, tc := range []struct {
		name        string
		prepare     func(tr *Transport)
		wantWithin  bool // does the resulting dial timeout fit the forwarding window?
		explanation string
	}{
		{"fresh transport, no dial finished yet", func(*Transport) {}, false,
			"avgDialTime starts at maxDialTimeout/2, which limitTimeout maps to the 30s ceiling"},
		{"fresh transport, upstream blackholed (every dial times out)", func(tr *Transport) { fail(tr, 200) }, false,
			"nothing ever succeeds to pull the average down, so the 30s ceiling is kept"},
		{"warmed by healthy dials", func(tr *Transport) { healthy(tr, 50) }, true,
			"the floor is 1s"},
		{"warmed, then upstream blackholed", func(tr *Transport) { healthy(tr, 50); fail(tr, 200) }, true,
			"failed dials move the average toward the floor-limited timeout, not past it: no escalation"},
		{"degraded upstream, dials legitimately take 3s", func(tr *Transport) {
			for range 50 {
				tr.updateDialTimeout(3 * time.Second)
			}
		}, false, "timeout is twice the average, so a 2.5s average already exceeds the window"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTransport("forward", "192.0.2.1:53")
			tc.prepare(tr)
			got := tr.dialTimeout()
			t.Logf("dial timeout = %v (window %v): %s", got, forwardWindow, tc.explanation)
			if (got <= forwardWindow) != tc.wantWithin {
				t.Fatalf("dial timeout %v: within window = %v, want %v", got, got <= forwardWindow, tc.wantWithin)
			}
			if !tc.wantWithin {
				t.Errorf("plain TCP dial may block for %v, longer than the %v forwarding window", got, forwardWindow)
			}
		})
	}
}
