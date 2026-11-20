package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/flowcontrol"
)

// These tests exercise InitKubeCache with the real client-go constructors and
// observe the limits on the clients it actually builds. They need no network:
// the rest.Config carries an in-memory http.RoundTripper.
//
// A directive is "applied" only if the constructed client sees it, so every
// assertion is made on the constructed clients, never on the plugin fields or
// on the rest.Config pointer after the fact.

// throttleClientConfig injects a synthetic rest.Config through the same
// Kubernetes.ClientConfig hook that the kubeconfig directive uses. Only
// ClientConfig() is called by getClientConfig.
type throttleClientConfig struct{ cfg *rest.Config }

func (s throttleClientConfig) ClientConfig() (*rest.Config, error) { return s.cfg, nil }
func (throttleClientConfig) RawConfig() (clientcmdapi.Config, error) {
	return clientcmdapi.Config{}, errors.New("not used")
}
func (throttleClientConfig) Namespace() (string, bool, error) {
	return "", false, errors.New("not used")
}
func (throttleClientConfig) ConfigAccess() clientcmd.ConfigAccess { return nil }

// throttleTransport is the in-memory "API server". Requests whose path starts
// with "/hold" block until release is closed or the request is cancelled. All
// other requests answer immediately.
type throttleTransport struct {
	mu        sync.Mutex
	entered   int // requests that reached this transport
	active    int
	maxActive int

	enteredCh chan string
	release   chan struct{}
	once      sync.Once
}

func newThrottleTransport() *throttleTransport {
	return &throttleTransport{enteredCh: make(chan string, 64), release: make(chan struct{})}
}

func (t *throttleTransport) releaseAll() { t.once.Do(func() { close(t.release) }) }

func (t *throttleTransport) snapshot() (entered, maxActive int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.entered, t.maxActive
}

func (t *throttleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.entered++
	t.active++
	if t.active > t.maxActive {
		t.maxActive = t.active
	}
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		t.active--
		t.mu.Unlock()
	}()

	select {
	case t.enteredCh <- r.URL.Path:
	default:
	}

	if strings.HasPrefix(r.URL.Path, "/hold") {
		select {
		case <-t.release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    r,
	}, nil
}

// waitEntered reports whether a request reached the transport within d.
func (t *throttleTransport) waitEntered(d time.Duration) bool {
	select {
	case <-t.enteredCh:
		return true
	case <-time.After(d):
		return false
	}
}

// countingWrap is a pre-existing WrapTransport, used to check composition.
type countingWrap struct{ calls atomic.Int32 }

func (c *countingWrap) wrap(rt http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		c.calls.Add(1)
		return rt.RoundTrip(r)
	})
}

type throttleFixture struct {
	k   *Kubernetes
	cfg *rest.Config // the pointer InitKubeCache received, for diagnostics only
	tr  *throttleTransport
	pre *countingWrap
}

type throttleSetup struct {
	// directives under test
	qps          float32
	burst        int
	maxInflight  int
	multicluster bool
	// values already present on the rest.Config handed to InitKubeCache
	inQPS   float32
	inBurst int
}

func newThrottleFixture(t *testing.T, s throttleSetup) (*throttleFixture, error) {
	t.Helper()
	tr := newThrottleTransport()
	t.Cleanup(tr.releaseAll)
	pre := &countingWrap{}

	cfg := &rest.Config{
		Host:          "http://k8s.invalid",
		Transport:     tr,
		QPS:           s.inQPS,
		Burst:         s.inBurst,
		WrapTransport: pre.wrap,
	}
	k := New([]string{"cluster.local."})
	k.ClientConfig = throttleClientConfig{cfg: cfg}
	k.apiQPS = s.qps
	k.apiBurst = s.burst
	k.apiMaxInflight = s.maxInflight
	if s.multicluster {
		k.opts.multiclusterZones = []string{"clusterset.local."}
	}

	_, _, err := k.InitKubeCache(context.Background())
	if err != nil {
		return nil, err
	}
	return &throttleFixture{k: k, cfg: cfg, tr: tr, pre: pre}, nil
}

// clients returns the constructed clients: the primary one, and the
// multicluster one or nil when multicluster is disabled.
func (f *throttleFixture) clients() (primary, mcs rest.Interface) {
	c := f.k.APIConn.(*dnsControl)
	primary = c.client.CoreV1().RESTClient()
	if c.mcsClient != nil {
		mcs = c.mcsClient.RESTClient()
	}
	return primary, mcs
}

func observedBurst(l flowcontrol.RateLimiter) int {
	n := 0
	for n < 10000 && l.TryAccept() {
		n++
	}
	return n
}

func probe(ctx context.Context, c rest.Interface, path string) error {
	_, err := c.Get().AbsPath(path).Do(ctx).Raw()
	return err
}

// TestAPIThrottleClientsSeeConfiguredRateLimits asserts that the QPS and burst
// seen by the constructed clients are the effective ones.
func TestAPIThrottleClientsSeeConfiguredRateLimits(t *testing.T) {
	const (
		clientGoDefaultQPS   = 5
		clientGoDefaultBurst = 10
	)
	tests := []struct {
		name      string
		setup     throttleSetup
		wantQPS   float32
		wantBurst int // 0: not asserted (the directive left it unspecified)
	}{
		// Burst is asserted on a token bucket, so it is only exact when the
		// refill is negligible. 0.5 QPS refills one token every two seconds.
		{"tighter than the input config", throttleSetup{qps: 0.5, burst: 7, inQPS: 33, inBurst: 44}, 0.5, 7},
		{"higher than the input config", throttleSetup{qps: 100, burst: 200, inQPS: 33, inBurst: 44}, 100, 200},
		{"higher than the client-go defaults", throttleSetup{qps: 100, burst: 200}, 100, 200},
		// client-go refuses a QPS without a burst, so the default burst is used.
		{"qps only, input config unset", throttleSetup{qps: 50}, 50, clientGoDefaultBurst},
		{"burst only, input config unset", throttleSetup{burst: 30}, clientGoDefaultQPS, 30},
		// Guards: nothing configured, so the input config must win.
		{"omitted directives keep the input config", throttleSetup{inQPS: 33, inBurst: 44}, 33, 44},
		{"omitted directives, input unset: client-go defaults", throttleSetup{}, clientGoDefaultQPS, clientGoDefaultBurst},
	}
	for _, multicluster := range []bool{false, true} {
		for _, tc := range tests {
			setup := tc.setup
			setup.multicluster = multicluster
			t.Run(fmt.Sprintf("multicluster=%v/%s", multicluster, tc.name), func(t *testing.T) {
				f, err := newThrottleFixture(t, setup)
				if err != nil {
					t.Fatalf("InitKubeCache failed: %v", err)
				}
				// Diagnostic: the assignments in InitKubeCache land on this object.
				t.Logf("rest.Config after InitKubeCache: QPS=%v Burst=%d (input was QPS=%v Burst=%d)",
					f.cfg.QPS, f.cfg.Burst, setup.inQPS, setup.inBurst)

				primary, mcs := f.clients()
				if multicluster != (mcs != nil) {
					t.Fatalf("multicluster client present=%v, want %v", mcs != nil, multicluster)
				}
				for name, c := range map[string]rest.Interface{"primary": primary, "multicluster": mcs} {
					if c == nil {
						continue
					}
					l := c.GetRateLimiter()
					if got := l.QPS(); got != tc.wantQPS {
						t.Errorf("%s client: QPS=%v, want %v", name, got, tc.wantQPS)
					}
					if tc.wantBurst > 0 {
						got := observedBurst(l)
						// Allow one token of refill for the fast-QPS cases.
						if got < tc.wantBurst || got > tc.wantBurst+2 {
							t.Errorf("%s client: burst=%d, want %d", name, got, tc.wantBurst)
						}
					}
				}
			})
		}
	}
}

// TestAPIThrottleClientsEnforceMaxInflight asserts that apiserver_max_inflight
// is enforced by the constructed clients and composes with a pre-existing
// WrapTransport.
func TestAPIThrottleClientsEnforceMaxInflight(t *testing.T) {
	for _, multicluster := range []bool{false, true} {
		for _, limit := range []int{1, 2} {
			for _, which := range []string{"primary", "multicluster"} {
				if which == "multicluster" && !multicluster {
					continue
				}
				t.Run(fmt.Sprintf("multicluster=%v/limit=%d/%s", multicluster, limit, which), func(t *testing.T) {
					// Input QPS is high so the rate limiter cannot interfere.
					f, err := newThrottleFixture(t, throttleSetup{maxInflight: limit, multicluster: multicluster, inQPS: 1000, inBurst: 1000})
					if err != nil {
						t.Fatalf("InitKubeCache failed: %v", err)
					}
					primary, mcs := f.clients()
					c := primary
					if which == "multicluster" {
						c = mcs
					}

					// Fill every slot with a held request.
					var wg sync.WaitGroup
					for i := 0; i < limit; i++ {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							_ = probe(context.Background(), c, fmt.Sprintf("/hold-%d", i))
						}(i)
					}
					for i := 0; i < limit; i++ {
						if !f.tr.waitEntered(2 * time.Second) {
							t.Fatalf("held request %d never reached the transport", i)
						}
					}

					// One more request must wait for a slot, not reach the transport.
					ctx, cancel := context.WithCancel(context.Background())
					extraErr := make(chan error, 1)
					go func() { extraErr <- probe(ctx, c, "/hold-extra") }()
					if f.tr.waitEntered(300 * time.Millisecond) {
						t.Errorf("request %d reached the transport while %d were held: max_inflight=%d not enforced", limit+1, limit, limit)
					}

					// Cancelling the waiting request must return promptly with the context error.
					cancel()
					select {
					case err := <-extraErr:
						if !errors.Is(err, context.Canceled) {
							t.Errorf("cancelled waiter returned %v, want context.Canceled", err)
						}
					case <-time.After(2 * time.Second):
						t.Errorf("cancelled waiter did not return")
					}

					entered, maxActive := f.tr.snapshot()
					if maxActive > limit {
						t.Errorf("max concurrent requests at the transport = %d, want <= %d (entered=%d)", maxActive, limit, entered)
					}

					// Releasing the held requests frees the slots (the cancelled waiter must not leak one).
					f.tr.releaseAll()
					wg.Wait()
					freeErr := make(chan error, 1)
					go func() { freeErr <- probe(context.Background(), c, "/free") }()
					select {
					case err := <-freeErr:
						if err != nil {
							t.Errorf("request after release failed: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Errorf("request after release blocked: slot leaked")
					}

					// The pre-existing wrapper must still run, i.e. the new wrapper composes with it.
					if f.pre.calls.Load() == 0 {
						t.Errorf("pre-existing WrapTransport was never invoked")
					}
				})
			}
		}
	}
}

// TestAPIThrottleMaxInflightIsPerClient documents that the limit applies to
// each client separately, as the README says. The wrapper creates one
// semaphore per wrapped transport and each client builds its own transport, so
// with multicluster enabled the primary and multicluster clients can each have
// one request in flight at the same time.
func TestAPIThrottleMaxInflightIsPerClient(t *testing.T) {
	f, err := newThrottleFixture(t, throttleSetup{maxInflight: 1, multicluster: true, inQPS: 1000, inBurst: 1000})
	if err != nil {
		t.Fatalf("InitKubeCache failed: %v", err)
	}
	primary, mcs := f.clients()
	for i, c := range []rest.Interface{primary, mcs} {
		go func(i int, c rest.Interface) { _ = probe(context.Background(), c, fmt.Sprintf("/hold-%d", i)) }(i, c)
	}
	for i := 0; i < 2; i++ {
		if !f.tr.waitEntered(2 * time.Second) {
			t.Fatalf("request %d never reached the transport: the limit is shared between the clients", i)
		}
	}
	if _, maxActive := f.tr.snapshot(); maxActive != 2 {
		t.Errorf("concurrent requests across both clients = %d, want 2", maxActive)
	}
}

// TestMaxInflightRoundTripperSlotIsReleasedAtResponseHeaders characterizes the
// current lifetime of a slot. It is not a statement of intended behavior.
//
// The wrapper releases its slot when RoundTrip returns, which for a streaming
// watch is when the response headers arrive, not when the body ends. Informers
// hold long-lived watches, so max_inflight bounds concurrent calls up to the
// response headers, not concurrent watch streams. Whether that is the
// contract is a separate decision from the initialization-order finding.
func TestMaxInflightRoundTripperSlotIsReleasedAtResponseHeaders(t *testing.T) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	defer pw1.Close()
	defer pw2.Close()
	bodies := []io.ReadCloser{pr1, pr2}
	var n atomic.Int32
	next := roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		i := n.Add(1) - 1
		return &http.Response{StatusCode: http.StatusOK, Body: bodies[i], Request: r}, nil
	})
	rt := newMaxInflightRoundTripper(next, 1)

	req := func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "http://k8s.invalid/watch", nil)
		return r
	}
	resp1, err := rt.RoundTrip(req())
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	// resp1's body (the "watch stream") is still open and unread here.

	done := make(chan error, 1)
	go func() {
		resp2, err := rt.RoundTrip(req())
		if err == nil {
			resp2.Body.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		t.Log("with max_inflight=1, a second stream was established while the first stream's body was still open")
	case <-time.After(time.Second):
		t.Fatal("second RoundTrip blocked while the first body was open: the slot now spans the response body. " +
			"If intentional, update this test and the README wording.")
	}
}
