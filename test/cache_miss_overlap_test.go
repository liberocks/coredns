package test

// Overlapping cache misses, end to end: a real CoreDNS instance running
// `cache` + `forward` in front of a real UDP upstream that counts the queries
// it receives. Identical concurrent client queries on a cold cache are counted
// at the upstream, not just at an in-process fake.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestCacheOverlappingMissesReachUpstream(t *testing.T) {
	const (
		clients         = 50
		upstreamLatency = 300 * time.Millisecond
	)

	var (
		mu       sync.Mutex
		perName  = map[string]int{}
		upstream atomic.Int32
	)
	up := dnstest.NewMultipleServer(func(w dns.ResponseWriter, r *dns.Msg) {
		upstream.Add(1)
		mu.Lock()
		perName[r.Question[0].Name]++
		mu.Unlock()
		time.Sleep(upstreamLatency)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{test.A(r.Question[0].Name + " 300 IN A 192.0.2.7")}
		w.WriteMsg(m)
	})
	defer up.Close()

	corefile := `.:0 {
		forward . ` + up.Addr + `
		cache 300
	}`
	i, udp, _, err := CoreDNSServerAndPorts(corefile)
	if err != nil {
		t.Fatalf("Could not get CoreDNS serving instance: %s", err)
	}
	defer i.Stop()

	query := func(name string) *dns.Msg {
		c := &dns.Client{Timeout: 5 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion(name, dns.TypeA)
		r, _, err := c.Exchange(m, udp)
		if err != nil {
			t.Errorf("query %s: %v", name, err)
			return nil
		}
		return r
	}

	// Cold burst: `clients` identical queries, all inside one upstream latency.
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := query("burst.example.org.")
			if r != nil && (r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1) {
				t.Errorf("invalid response: %v", r)
			}
		}()
	}
	close(start)
	wg.Wait()

	mu.Lock()
	burst := perName["burst.example.org."]
	mu.Unlock()
	t.Logf("cold burst: %d identical client queries -> %d upstream queries for the same name/type", clients, burst)

	// Warm: the same query again must be a pure cache hit.
	before := upstream.Load()
	if r := query("burst.example.org."); r == nil || len(r.Answer) != 1 {
		t.Fatalf("warm query failed: %v", r)
	}
	if after := upstream.Load(); after != before {
		t.Fatalf("warm query reached upstream: %d -> %d", before, after)
	}

	// Control: a single serial query for a new name produces exactly one upstream query.
	query("single.example.org.")
	mu.Lock()
	single := perName["single.example.org."]
	mu.Unlock()
	t.Logf("control: 1 serial client query -> %d upstream query", single)
	if single != 1 {
		t.Fatalf("control: want 1 upstream query for a single serial request, got %d", single)
	}

	// Baseline (no coalescing): essentially every client that arrived inside the
	// upstream latency window triggers its own upstream query.
	if burst < 2 {
		t.Fatalf("duplicate upstream queries not reproduced: %d clients -> %d upstream queries", clients, burst)
	}
}
