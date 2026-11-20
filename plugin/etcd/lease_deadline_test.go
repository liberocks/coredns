package etcd

// Finding 08: etcd lease TTL lookups lose the DNS request deadline.
//
// These tests drive the real etcd v3 client (and the real Records/ServeDNS
// code paths) against an in-process fake etcd gRPC server. The fake server
// implements only KV.Range and Lease.LeaseTimeToLive. For every lease RPC it
// records the deadline the server saw (gRPC propagates the client's context
// deadline on the wire), whether the RPC was cancelled, and the call order.
//
// Tests named ...Control... and ...Characterization... describe behavior that
// must hold before and after any fix. The remaining tests assert the desired
// deadline/cancellation behavior of the lease lookup.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/etcd/msg"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	etcdcv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const leaseTestQName = "svc.skydns.local."

// leaseCall is what the fake server observed for one LeaseTimeToLive RPC.
type leaseCall struct {
	ID          int64
	Start       time.Time
	HadDeadline bool
	Deadline    time.Time
	End         time.Time
	Outcome     string // "released", "ctx-done", "slept", "answered", "failed"
}

// leaseHook decides how the fake answers one lease RPC.
type leaseHook func(ctx context.Context, f *fakeEtcd, c *leaseCall) (ttl int64, outcome string, err error)

type fakeEtcd struct {
	pb.UnimplementedKVServer
	pb.UnimplementedLeaseServer

	kvs       []*mvccpb.KeyValue
	leaseHook leaseHook

	release     chan struct{} // closed by the test to free every blocked handler
	releaseOnce sync.Once
	started     chan struct{} // one token per lease RPC that reached the server

	mu         sync.Mutex
	rangeGate  chan struct{} // when non-nil, Range blocks until closed/released/cancelled
	rangeCalls int
	calls      []*leaseCall
}

func (f *fakeEtcd) releaseAll() { f.releaseOnce.Do(func() { close(f.release) }) }

func (f *fakeEtcd) setRangeGate(g chan struct{}) {
	f.mu.Lock()
	f.rangeGate = g
	f.mu.Unlock()
}

func (f *fakeEtcd) rangeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rangeCalls
}

func (f *fakeEtcd) snapshot() []leaseCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]leaseCall, len(f.calls))
	for i, c := range f.calls {
		out[i] = *c
	}
	return out
}

func (f *fakeEtcd) Range(ctx context.Context, req *pb.RangeRequest) (*pb.RangeResponse, error) {
	f.mu.Lock()
	f.rangeCalls++
	gate := f.rangeGate
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-f.release:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
	}
	var out []*mvccpb.KeyValue
	for _, kv := range f.kvs {
		if bytes.HasPrefix(kv.Key, req.Key) {
			out = append(out, kv)
		}
	}
	return &pb.RangeResponse{Header: &pb.ResponseHeader{}, Kvs: out, Count: int64(len(out))}, nil
}

func (f *fakeEtcd) LeaseTimeToLive(ctx context.Context, req *pb.LeaseTimeToLiveRequest) (*pb.LeaseTimeToLiveResponse, error) {
	c := &leaseCall{ID: req.ID, Start: time.Now()}
	c.Deadline, c.HadDeadline = ctx.Deadline()
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	select {
	case f.started <- struct{}{}:
	default:
	}

	ttl, outcome, err := f.leaseHook(ctx, f, c)

	f.mu.Lock()
	c.End = time.Now()
	c.Outcome = outcome
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &pb.LeaseTimeToLiveResponse{Header: &pb.ResponseHeader{}, ID: req.ID, TTL: ttl, GrantedTTL: ttl}, nil
}

// holdUntilReleased blocks until the test releases the fake or the RPC is cancelled.
func holdUntilReleased(ttl int64) leaseHook {
	return func(ctx context.Context, f *fakeEtcd, _ *leaseCall) (int64, string, error) {
		select {
		case <-f.release:
			return ttl, "released", nil
		case <-ctx.Done():
			return 0, "ctx-done", status.FromContextError(ctx.Err()).Err()
		}
	}
}

// slowAnswer answers with ttl after d, unless cancelled or released first.
func slowAnswer(d time.Duration, ttl int64) leaseHook {
	return func(ctx context.Context, f *fakeEtcd, _ *leaseCall) (int64, string, error) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return ttl, "slept", nil
		case <-f.release:
			return ttl, "released", nil
		case <-ctx.Done():
			return 0, "ctx-done", status.FromContextError(ctx.Err()).Err()
		}
	}
}

func answerTTL(ttl int64) leaseHook {
	return func(context.Context, *fakeEtcd, *leaseCall) (int64, string, error) {
		return ttl, "answered", nil
	}
}

type fixture struct {
	t   *testing.T
	f   *fakeEtcd
	e   *Etcd
	srv *grpc.Server
	lis net.Listener
	wg  sync.WaitGroup

	// closeClientFirst is set by tests that kill the fake server: releasing a
	// dead server cannot free a blocked client call, so teardown closes the
	// client first (which fails every pending RPC) before waiting.
	closeClientFirst bool
}

func newFixture(t *testing.T, kvs []*mvccpb.KeyValue, hook leaseHook) *fixture {
	t.Helper()
	f := &fakeEtcd{
		kvs:       kvs,
		leaseHook: hook,
		release:   make(chan struct{}),
		started:   make(chan struct{}, 4096),
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterKVServer(srv, f)
	pb.RegisterLeaseServer(srv, f)
	go srv.Serve(lis)

	cli, err := etcdcv3.New(etcdcv3.Config{Endpoints: []string{lis.Addr().String()}, DialTimeout: 5 * time.Second})
	if err != nil {
		srv.Stop()
		t.Fatal(err)
	}
	fx := &fixture{
		t: t, f: f, srv: srv, lis: lis,
		e: &Etcd{Client: cli, PathPrefix: "skydns", Zones: []string{"skydns.local."}},
	}
	t.Cleanup(func() {
		// Deterministic teardown: free every blocked handler, wait for every
		// goroutine the test started, then close client and server.
		f.releaseAll()
		if fx.closeClientFirst {
			cli.Close()
		}
		done := make(chan struct{})
		go func() { fx.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("fixture goroutines did not exit at teardown")
		}
		cli.Close()
		srv.Stop()
	})
	return fx
}

// async runs fn in a goroutine tracked by the fixture.
func (fx *fixture) async(fn func()) {
	fx.wg.Add(1)
	go func() {
		defer fx.wg.Done()
		fn()
	}()
}

func (fx *fixture) waitLeaseStarts(n int, within time.Duration) {
	fx.t.Helper()
	deadline := time.After(within)
	for i := 0; i < n; i++ {
		select {
		case <-fx.f.started:
		case <-deadline:
			fx.t.Fatalf("only %d of %d lease RPCs reached the fake server within %v", i, n, within)
		}
	}
}

func leaseKV(name string, idx int, lease int64) *mvccpb.KeyValue {
	return &mvccpb.KeyValue{
		Key:   []byte("/skydns/local/skydns/svc/" + name),
		Value: []byte(fmt.Sprintf(`{"host":"10.0.0.%d"}`, idx)),
		Lease: lease,
	}
}

func leaseQuery() request.Request {
	m := new(dns.Msg)
	m.SetQuestion(leaseTestQName, dns.TypeA)
	return request.Request{Req: m}
}

type recordsResult struct {
	recs    []msg.Service
	err     error
	elapsed time.Duration
}

// startRecords runs Records in the background and reports its result.
func (fx *fixture) startRecords(ctx context.Context) <-chan recordsResult {
	ch := make(chan recordsResult, 1)
	start := time.Now()
	fx.async(func() {
		recs, err := fx.e.Records(ctx, leaseQuery(), false)
		ch <- recordsResult{recs, err, time.Since(start)}
	})
	return ch
}

func logCalls(t *testing.T, t0 time.Time, calls []leaseCall) {
	t.Helper()
	for i, c := range calls {
		end := "in flight"
		if !c.End.IsZero() {
			end = fmt.Sprintf("end=+%v", c.End.Sub(t0).Round(time.Millisecond))
		}
		t.Logf("  lease call %d: id=%d start=+%v %s outcome=%q server-saw-deadline=%v",
			i+1, c.ID, c.Start.Sub(t0).Round(time.Millisecond), end, c.Outcome, c.HadDeadline)
	}
}

// ---------------------------------------------------------------------------
// Controls and characterization: these must pass before and after a fix.
// ---------------------------------------------------------------------------

// An unleased record must never trigger a lease RPC.
func TestLeaseLookupControlUnleasedRecordMakesNoLeaseRPC(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 0), leaseKV("b", 2, 0)}, holdUntilReleased(60))
	recs, err := fx.e.Records(context.Background(), leaseQuery(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if n := len(fx.f.snapshot()); n != 0 {
		t.Fatalf("unleased records caused %d lease RPCs, want 0", n)
	}
	for _, r := range recs {
		if r.TTL != defaultTTL {
			t.Errorf("TTL = %d, want default %d", r.TTL, defaultTTL)
		}
	}
}

// The parent's context already works on the range call (finding: "record
// whether the parent's context still works on the range call").
func TestLeaseLookupControlRangeHonorsCallerDeadline(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, answerTTL(60))
	fx.f.setRangeGate(make(chan struct{})) // never opened by the test
	const d = 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	res := <-fx.startRecords(ctx)
	t.Logf("range blocked, caller deadline %v: Records returned after %v, err=%v", d, res.elapsed.Round(time.Millisecond), res.err)
	if res.err == nil {
		t.Fatal("expected an error from a blocked range call")
	}
	if res.elapsed > d+time.Second {
		t.Fatalf("range call did not honor the caller deadline: returned after %v", res.elapsed)
	}
	if n := len(fx.f.snapshot()); n != 0 {
		t.Fatalf("lease RPC issued although range never returned: %d", n)
	}
}

// Existing TTL semantics with a live caller: lease TTL is clamped, the smaller
// of lease and service TTL wins, and lease errors fall back.
func TestLeaseLookupCharacterizationTTLSemantics(t *testing.T) {
	tests := []struct {
		name       string
		hook       leaseHook
		serviceTTL uint32
		min, max   uint32
		want       uint32
	}{
		{"lease TTL inside bounds", answerTTL(120), 0, 0, 0, 120},
		{"lease TTL clamped up to default min", answerTTL(5), 0, 0, 0, defaultLeaseMinTTL},
		{"lease TTL clamped down to default max", answerTTL(10_000_000), 0, 0, 0, defaultLeaseMaxTTL},
		{"lease TTL clamped to configured bounds", answerTTL(5), 0, 90, 600, 90},
		{"smaller service TTL wins", answerTTL(500), 100, 0, 0, 100},
		{"smaller lease TTL wins", answerTTL(100), 500, 0, 0, 100},
		{"expired lease (TTL -1) falls back to default", answerTTL(-1), 0, 0, 0, defaultTTL},
		{"lease RPC error falls back to default", func(context.Context, *fakeEtcd, *leaseCall) (int64, string, error) {
			return 0, "failed", status.Error(codes.NotFound, "lease not found")
		}, 0, 0, 0, defaultTTL},
		{"lease RPC error falls back to service TTL", func(context.Context, *fakeEtcd, *leaseCall) (int64, string, error) {
			return 0, "failed", status.Error(codes.NotFound, "lease not found")
		}, 77, 0, 0, 77},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := leaseKV("a", 1, 1001)
			if tt.serviceTTL != 0 {
				kv.Value = []byte(fmt.Sprintf(`{"host":"10.0.0.1","ttl":%d}`, tt.serviceTTL))
			}
			fx := newFixture(t, []*mvccpb.KeyValue{kv}, tt.hook)
			fx.e.MinLeaseTTL, fx.e.MaxLeaseTTL = tt.min, tt.max
			recs, err := fx.e.Records(context.Background(), leaseQuery(), false)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 1 || recs[0].TTL != tt.want {
				t.Fatalf("records=%+v, want one record with TTL %d", recs, tt.want)
			}
			if n := len(fx.f.snapshot()); n != 1 {
				t.Fatalf("lease RPC count = %d, want 1", n)
			}
		})
	}
}

// Diagnostic signature used when reading production goroutine profiles: a stuck
// lease lookup shows plugin/etcd.(*Etcd).TTL above clientv3 TimeToLive.
func TestLeaseLookupStackSignature(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
	_ = fx.startRecords(context.Background())
	fx.waitLeaseStarts(1, 5*time.Second)

	var hit string
	for i := 0; i < 50 && hit == ""; i++ {
		for _, g := range goroutineStacks() {
			if isLeaseLookupStack(g) && strings.Contains(g, "TimeToLive") {
				hit = g
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if hit == "" {
		t.Fatal("no goroutine blocked in (*Etcd).TTL -> TimeToLive")
	}
	t.Logf("goroutine blocked in the lease lookup (trimmed):\n%s", trimStack(hit, 30))
}

// ---------------------------------------------------------------------------
// Regression tests for the finding: desired deadline behavior.
// ---------------------------------------------------------------------------

// The lease RPC must carry the caller's deadline and Records must give up by
// then instead of waiting for a slow lease lookup.
func TestLeaseLookupPropagatesCallerDeadline(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
	const d = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	t0 := time.Now()
	done := fx.startRecords(ctx)
	fx.waitLeaseStarts(1, 5*time.Second)

	var res recordsResult
	returned := true
	select {
	case res = <-done:
	case <-time.After(d + time.Second):
		returned = false
	}
	calls := fx.f.snapshot()
	t.Logf("caller deadline %v; range calls=%d; Records returned by deadline+1s: %v", d, fx.f.rangeCount(), returned)
	logCalls(t, t0, calls)

	if !returned {
		// Free the fake so we can show what the held request finally yields.
		fx.f.releaseAll()
		res = <-done
		t.Errorf("Records ignored the %v caller deadline and was still blocked on the lease RPC %v later", d, time.Since(t0).Round(time.Millisecond))
		t.Logf("after the lease RPC was released at ~%v: Records returned %d record(s), err=%v (work completed for a caller whose deadline had long passed)",
			res.elapsed.Round(time.Millisecond), len(res.recs), res.err)
	}
	if len(calls) == 1 && !calls[0].HadDeadline {
		t.Errorf("lease RPC reached the server with no deadline although the caller's context had one")
	}
}

// Cancelling the caller while the lease RPC is in flight must cancel the RPC
// and let Records return.
func TestLeaseLookupObservesCallerCancellation(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
	ctx, cancel := context.WithCancel(context.Background())
	t0 := time.Now()
	done := fx.startRecords(ctx)
	fx.waitLeaseStarts(1, 5*time.Second)

	cancel() // caller goes away while the lease RPC is in flight
	cancelledAt := time.Now()

	returned := true
	select {
	case <-done:
	case <-time.After(time.Second):
		returned = false
	}
	// Give the cancellation time to reach the server as well.
	time.Sleep(200 * time.Millisecond)
	calls := fx.f.snapshot()
	t.Logf("caller cancelled at +%v; Records returned within 1s: %v", cancelledAt.Sub(t0).Round(time.Millisecond), returned)
	logCalls(t, t0, calls)

	if !returned {
		t.Errorf("Records did not return within 1s of the caller being cancelled")
	}
	if len(calls) == 1 && calls[0].Outcome != "ctx-done" {
		t.Errorf("cancellation never reached the lease RPC (server-side outcome %q)", calls[0].Outcome)
	}
}

// Serial lease calls must not run past an overall request deadline: no lease
// call may start after it expires. An unleased record must stay a control.
func TestLeaseLookupMultiRecordStopsAfterDeadline(t *testing.T) {
	const (
		perCall = 600 * time.Millisecond
		d       = 700 * time.Millisecond
	)
	kvs := []*mvccpb.KeyValue{
		leaseKV("a", 1, 1001),
		leaseKV("b", 2, 1002),
		leaseKV("c", 3, 1003),
		leaseKV("z-unleased", 4, 0),
	}
	fx := newFixture(t, kvs, slowAnswer(perCall, 60))
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	t0 := time.Now()
	res := <-fx.startRecords(ctx)
	calls := fx.f.snapshot()
	t.Logf("deadline %v, each lease RPC takes %v: Records returned after %v with %d record(s), err=%v",
		d, perCall, res.elapsed.Round(time.Millisecond), len(res.recs), res.err)
	logCalls(t, t0, calls)

	var order []int64
	late := 0
	for _, c := range calls {
		order = append(order, c.ID)
		if c.Start.Sub(t0) > d {
			late++
		}
		if c.ID == 0 {
			t.Errorf("the unleased control record triggered a lease RPC")
		}
	}
	t.Logf("lease call order: %v; calls started after the deadline: %d", order, late)
	if late > 0 {
		t.Errorf("%d lease call(s) started after the request deadline had expired", late)
	}
	if res.elapsed > d+500*time.Millisecond {
		t.Errorf("Records ran %v for a %v deadline (serial lease delays added up)", res.elapsed.Round(time.Millisecond), d)
	}
}

// Full ServeDNS path: the handler must not outlive the request deadline.
func TestLeaseLookupServeDNSHonorsDeadline(t *testing.T) {
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
	const d = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(leaseTestQName, dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	type out struct {
		rcode   int
		err     error
		elapsed time.Duration
	}
	done := make(chan out, 1)
	start := time.Now()
	fx.async(func() {
		rc, err := fx.e.ServeDNS(ctx, rec, m)
		done <- out{rc, err, time.Since(start)}
	})
	fx.waitLeaseStarts(1, 5*time.Second)

	select {
	case o := <-done:
		t.Logf("ServeDNS returned after %v rcode=%d err=%v", o.elapsed.Round(time.Millisecond), o.rcode, o.err)
	case <-time.After(d + time.Second):
		fx.f.releaseAll()
		o := <-done
		t.Errorf("ServeDNS still blocked %v after a %v request deadline; it only returned after the lease RPC was released (at %v, rcode=%d, reply written=%v)",
			time.Second, d, o.elapsed.Round(time.Millisecond), o.rcode, rec.Msg != nil)
	}
}

// Many concurrent requests blocked on slow lease lookups: after their
// deadlines pass, none may remain in flight. Also records goroutine counts
// before, during and after, to show retention and recovery.
func TestLeaseLookupConcurrentRequestsDoNotAccumulate(t *testing.T) {
	const (
		n = 40
		d = 300 * time.Millisecond
	)
	fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
	settle := func() int { time.Sleep(200 * time.Millisecond); return runtime.NumGoroutine() }
	before := settle()

	var inflight atomic.Int64
	for i := 0; i < n; i++ {
		fx.async(func() {
			ctx, cancel := context.WithTimeout(context.Background(), d)
			defer cancel()
			m := new(dns.Msg)
			m.SetQuestion(leaseTestQName, dns.TypeA)
			inflight.Add(1)
			defer inflight.Add(-1)
			_, _ = fx.e.ServeDNS(ctx, dnstest.NewRecorder(&test.ResponseWriter{}), m)
		})
	}
	fx.waitLeaseStarts(n, 10*time.Second)
	time.Sleep(d + time.Second) // every request deadline has now passed
	during := runtime.NumGoroutine()
	stuck := inflight.Load()
	inTTL := 0
	for _, g := range goroutineStacks() {
		if isLeaseLookupStack(g) {
			inTTL++
		}
	}
	t.Logf("%d requests, deadline %v each; goroutines before=%d, 1s after all deadlines=%d (+%d); requests still in flight=%d; goroutines inside (*Etcd).TTL=%d",
		n, d, before, during, during-before, stuck, inTTL)

	fx.f.releaseAll()
	deadline := time.Now().Add(5 * time.Second)
	for inflight.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	after := settle()
	t.Logf("after the lease RPCs were released: in flight=%d, goroutines=%d (before=%d)", inflight.Load(), after, before)

	if stuck != 0 {
		t.Errorf("%d of %d requests were still in flight 1s after their %v deadline", stuck, n, d)
	}
}

// With no caller deadline (the stock CoreDNS server context), the range call is
// bounded by etcdTimeout. The lease RPC must be bounded by it too.
func TestLeaseLookupBoundedByEtcdTimeoutWithoutCallerDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about etcdTimeout")
	}
	t.Run("range is bounded (control)", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, answerTTL(60))
		fx.f.setRangeGate(make(chan struct{}))
		res := <-fx.startRecords(context.Background())
		t.Logf("blocked range, no caller deadline: Records returned after %v, err=%v", res.elapsed.Round(10*time.Millisecond), res.err)
		if res.err == nil || res.elapsed > etcdTimeout+time.Second {
			t.Fatalf("range call not bounded by etcdTimeout: elapsed=%v err=%v", res.elapsed, res.err)
		}
	})
	t.Run("lease is bounded", func(t *testing.T) {
		t.Parallel()
		fx := newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, holdUntilReleased(60))
		done := fx.startRecords(context.Background())
		fx.waitLeaseStarts(1, 5*time.Second)
		select {
		case res := <-done:
			t.Logf("blocked lease, no caller deadline: Records returned after %v, err=%v", res.elapsed.Round(10*time.Millisecond), res.err)
		case <-time.After(etcdTimeout + time.Second):
			t.Errorf("lease RPC still blocked %v after start; only the range call is bounded by etcdTimeout (%v)", etcdTimeout+time.Second, etcdTimeout)
		}
	})
}

// etcd becomes unreachable between the range and the lease RPC. The client
// defaults to WaitForReady(true), so an unbounded context blocks until the
// connection returns.
func TestLeaseLookupBackendLostAfterRangeIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about etcdTimeout")
	}
	var fx *fixture
	killed := make(chan struct{})
	fx = newFixture(t, []*mvccpb.KeyValue{leaseKV("a", 1, 1001)}, func(ctx context.Context, f *fakeEtcd, _ *leaseCall) (int64, string, error) {
		// Take the whole backend down while the lease RPC is in flight.
		go func() { fx.lis.Close(); fx.srv.Stop(); close(killed) }()
		select {
		case <-f.release:
			return 60, "released", nil
		case <-ctx.Done():
			return 0, "ctx-done", status.FromContextError(ctx.Err()).Err()
		}
	})
	fx.closeClientFirst = true
	t0 := time.Now()
	done := fx.startRecords(context.Background())
	fx.waitLeaseStarts(1, 5*time.Second)
	<-killed
	select {
	case res := <-done:
		t.Logf("backend lost after range: Records returned after %v, err=%v", time.Since(t0).Round(10*time.Millisecond), res.err)
	case <-time.After(etcdTimeout + time.Second):
		t.Errorf("backend lost after the range call: Records still blocked %v later (no bound on the lease RPC)", time.Since(t0).Round(10*time.Millisecond))
	}
}

// ---------------------------------------------------------------------------

// The range call and all lease calls share one etcdTimeout budget. With several
// distinct leases and a stalled etcd, the request must give up after one budget,
// not wait once per record, and must not start more lease calls after that.
func TestLeaseLookupMultiRecordSharesOneBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about etcdTimeout")
	}
	kvs := []*mvccpb.KeyValue{
		leaseKV("a", 1, 1001),
		leaseKV("b", 2, 1002),
		leaseKV("c", 3, 1003),
	}
	fx := newFixture(t, kvs, holdUntilReleased(60))
	t0 := time.Now()
	done := fx.startRecords(context.Background())
	fx.waitLeaseStarts(1, 5*time.Second)
	select {
	case res := <-done:
		calls := fx.f.snapshot()
		t.Logf("3 leased records, stalled etcd, no caller deadline: Records returned after %v with err=%v", res.elapsed.Round(10*time.Millisecond), res.err)
		logCalls(t, t0, calls)
		if res.err == nil {
			t.Error("expected an error once the budget was used up")
		}
		if len(calls) != 1 {
			t.Errorf("lease RPC count = %d, want 1 (no new lease call after the budget is used up)", len(calls))
		}
	case <-time.After(etcdTimeout + time.Second):
		t.Errorf("Records still blocked %v after the first lease RPC started", etcdTimeout+time.Second)
	}
}

// isLeaseLookupStack reports whether a goroutine stack is inside the etcd
// plugin's lease TTL processing (TTL, or a renamed private helper after a fix).
func isLeaseLookupStack(g string) bool {
	return strings.Contains(g, "plugin/etcd.(*Etcd).TTL") || strings.Contains(g, "plugin/etcd.(*Etcd).ttl")
}

func goroutineStacks() []string {
	buf := make([]byte, 1<<22)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	return strings.Split(string(buf), "\n\n")
}

// trimStack keeps only the function-name lines of a goroutine stack (file and
// line lines are indented with a tab), so the call chain fits in a test log.
func trimStack(s string, max int) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "\t") {
			continue
		}
		out = append(out, l)
		if len(out) == max {
			break
		}
	}
	return strings.Join(out, "\n")
}
