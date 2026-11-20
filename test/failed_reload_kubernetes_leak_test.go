package test

// Finding 04: does a failed reload leave Kubernetes informers running?
//
// This is the end-to-end counterpart of plugin/reload/failed_restart_lifecycle_test.go.
// Nothing about CoreDNS or Caddy is faked here except the Kubernetes API server:
//
//   - the real `dns` server type, the real `kubernetes` plugin and its real
//     client-go informers;
//   - the real, pinned Caddy Instance.Restart, called exactly as plugin/reload
//     calls it;
//   - a failure injected the way it happens in production: the new Corefile adds
//     a server block whose TCP port is already taken, so startServers fails
//     AFTER the Kubernetes startup callback has run.
//
// The API server is an httptest server that counts open watch connections, which
// is the signal an operator would read from API audit logs or apiserver metrics.
// It also serves a few thousand Services, so retained informer state is visible
// in the live heap.
//
// Each scenario runs in a child process: the Kubernetes plugin installs a
// process-global klog logger and goroutine/heap counts must not include other
// tests' informers. The tests assert what CoreDNS does TODAY, so
// "TestFailedReloadKubernetesLeak/failed-late" passes because the defect is
// present; flip its expectations if the lifecycle is fixed.
//
// Run (without -race):
//
//	go test ./test -run '^TestFailedReloadKubernetesLeak$' -count=1 -v
//
// Do not add -race. Every scenario, controls included, then fails on an
// unrelated, pre-existing race: plugin/kubernetes/setup.go calls
// klog.SetLogger on each reload while earlier informers' reflectors read klog's
// global logger. It is independent of this finding.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	leakChildEnv    = "COREDNS_FAILED_RELOAD_LEAK_TEST"
	leakServices    = 5000 // enough that one informer cache is visible in the heap.
	leakReloadTries = 5
)

// countingAPI is a minimal Kubernetes API server that records watch activity.
type countingAPI struct {
	srv *httptest.Server

	mu           sync.Mutex
	activeWatch  map[string]int
	totalWatches int
	totalLists   int
}

func (a *countingAPI) active() (total int, byPath map[string]int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	byPath = map[string]int{}
	for p, n := range a.activeWatch {
		byPath[p] = n
		total += n
	}
	return total, byPath
}

func (a *countingAPI) requests() (watches, lists int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.totalWatches, a.totalLists
}

func newCountingAPI(t *testing.T) (*countingAPI, string) {
	t.Helper()

	services := make([]k8sruntime.RawExtension, 0, leakServices)
	for i := 0; i < leakServices; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", 96+i/65025, (i/255)%255, i%255+1)
		services = append(services, k8sruntime.RawExtension{Object: &corev1.Service{
			TypeMeta: metav1.TypeMeta{Kind: "Service", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("svc-%d", i), Namespace: "leak", ResourceVersion: "1",
				UID:         "00000000-0000-0000-0000-000000000000",
				Labels:      map[string]string{"app": fmt.Sprintf("app-%d", i%97)},
				Annotations: map[string]string{"note": strings.Repeat("x", 64)},
			},
			Spec: corev1.ServiceSpec{
				Type: corev1.ServiceTypeClusterIP, ClusterIP: ip, ClusterIPs: []string{ip},
				Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
			},
		}})
	}
	resources := map[string]struct {
		kind, apiVersion string
		objects          []k8sruntime.RawExtension
	}{
		"/api/v1/namespaces": {"Namespace", "v1", []k8sruntime.RawExtension{{Object: &corev1.Namespace{
			TypeMeta:   metav1.TypeMeta{Kind: "Namespace", APIVersion: "v1"},
			ObjectMeta: metav1.ObjectMeta{Name: "leak", ResourceVersion: "1"},
		}}}},
		"/api/v1/services":                         {"Service", "v1", services},
		"/apis/discovery.k8s.io/v1/endpointslices": {"EndpointSlice", "discovery.k8s.io/v1", nil},
	}

	api := &countingAPI{activeWatch: map[string]int{}}
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, ok := resources[r.URL.Path]
		if !ok || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		if r.URL.Query().Get("watch") != "true" {
			api.mu.Lock()
			api.totalLists++
			api.mu.Unlock()
			_ = enc.Encode(&metav1.List{
				TypeMeta: metav1.TypeMeta{Kind: resource.kind + "List", APIVersion: resource.apiVersion},
				ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: resource.objects,
			})
			return
		}

		api.mu.Lock()
		api.totalWatches++
		api.activeWatch[r.URL.Path]++
		api.mu.Unlock()
		defer func() {
			api.mu.Lock()
			api.activeWatch[r.URL.Path]--
			api.mu.Unlock()
		}()

		// client-go may use a streaming initial list (sendInitialEvents) or
		// classic list-then-watch; serve both.
		if r.URL.Query().Get("sendInitialEvents") == "true" {
			send := func(eventType string, obj k8sruntime.Object) {
				_ = enc.Encode(struct {
					Type   string            `json:"type"`
					Object k8sruntime.Object `json:"object"`
				}{eventType, obj})
			}
			for _, o := range resource.objects {
				send("ADDED", o.Object)
			}
			send("BOOKMARK", &metav1.PartialObjectMetadata{
				TypeMeta: metav1.TypeMeta{Kind: resource.kind, APIVersion: resource.apiVersion},
				ObjectMeta: metav1.ObjectMeta{ResourceVersion: "1", Annotations: map[string]string{
					metav1.InitialEventsAnnotationKey: "true",
				}},
			})
		}
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(func() {
		api.srv.CloseClientConnections()
		api.srv.Close()
	})

	config, err := clientcmd.Write(clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{"test": {Server: api.srv.URL}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"test": {}},
		Contexts:       map[string]*clientcmdapi.Context{"test": {Cluster: "test", AuthInfo: "test"}},
		CurrentContext: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}
	return api, path
}

// leakSample is one row of the per-process timeline.
type leakSample struct {
	label       string
	watches     int            // open watch connections seen by the API server
	byPath      map[string]int // ... by resource
	goroutines  int
	dnsControls int // goroutines parked in kubernetes.(*dnsControl).Run: one per started controller
	reflectors  int // goroutines inside client-go (*Reflector).ListAndWatch*
	heapMiB     float64
}

func takeLeakSample(api *countingAPI, label string) leakSample {
	// Let any in-flight connection teardown settle, then collect garbage so
	// HeapAlloc approximates live heap.
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	var buf bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)
	s := leakSample{label: label, heapMiB: float64(ms.HeapAlloc) / (1 << 20), goroutines: runtime.NumGoroutine()}
	for _, g := range strings.Split(buf.String(), "\n\n") {
		// Ignore the "created by ..." trailer: it names the parent of every
		// goroutine dnsControl.Run spawns and would be counted again.
		frames, _, _ := strings.Cut(g, "\ncreated by ")
		if strings.Contains(frames, "plugin/kubernetes.(*dnsControl).Run(") {
			s.dnsControls++
		}
		if strings.Contains(frames, "tools/cache.(*Reflector).ListAndWatch") {
			s.reflectors++
		}
	}
	s.watches, s.byPath = api.active()
	return s
}

func (s leakSample) String() string {
	return fmt.Sprintf("MEASURE %-44s api_watches=%-3d dnsControl.Run=%-2d reflector_goroutines=%-3d goroutines=%-4d heap=%.1fMiB",
		s.label, s.watches, s.dnsControls, s.reflectors, s.goroutines, s.heapMiB)
}

// waitForWatches waits for the API server to see the wanted number of open
// watches, returning the last observed count.
func waitForWatches(api *countingAPI, want int, d time.Duration) int {
	deadline := time.Now().Add(d)
	for {
		n, _ := api.active()
		if n == want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// blockTCPPort holds a TCP port so that CoreDNS cannot bind it.
func blockTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

func lookupLeakService(t *testing.T, udp string) {
	t.Helper()
	_, port, err := net.SplitHostPort(udp)
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	m.SetQuestion("svc-4321.leak.svc.cluster.local.", dns.TypeA)
	r, err := dns.Exchange(m, net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatalf("DNS lookup against the live instance failed: %v", err)
	}
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("DNS lookup against the live instance returned %s", r)
	}
}

func TestFailedReloadKubernetesLeak(t *testing.T) {
	scenarios := []string{"failed-late", "failed-early-control", "successful-control"}
	for _, scenario := range scenarios {
		t.Run(scenario, func(t *testing.T) {
			if os.Getenv(leakChildEnv) != t.Name() {
				pattern := "^" + strings.ReplaceAll(t.Name(), "/", "$/^") + "$"
				cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+pattern, "-test.v", "-test.timeout=120s")
				cmd.Env = append(os.Environ(), leakChildEnv+"="+t.Name())
				out, err := cmd.CombinedOutput()
				for _, line := range strings.Split(string(out), "\n") {
					if strings.Contains(line, "MEASURE") || strings.Contains(line, "EVIDENCE") {
						t.Log(strings.TrimSpace(line))
					}
				}
				if err != nil {
					t.Fatalf("isolated scenario failed: %v\n%s", err, out)
				}
				return
			}
			runLeakScenario(t, scenario)
		})
	}
}

func runLeakScenario(t *testing.T, scenario string) {
	caddy.Quiet = true
	api, kubeconfig := newCountingAPI(t)
	k8sBlock := func(extra string) string {
		return fmt.Sprintf("kubernetes cluster.local {\n kubeconfig %q\n startup_timeout 20s\n %s\n}", filepath.ToSlash(kubeconfig), extra)
	}
	good := fmt.Sprintf(".:0 {\n %s\n}\n", k8sBlock(""))

	cur, udp, _, err := CoreDNSServerAndPorts(good)
	if err != nil {
		t.Fatal(err)
	}
	shutdownLive := func() {
		// Full shutdown of the live instance, the way coremain does on SIGTERM.
		if cur == nil {
			return
		}
		for _, err := range cur.ShutdownCallbacks() {
			t.Log(err)
		}
		_ = cur.Stop()
		cur = nil
	}
	t.Cleanup(shutdownLive)
	lookupLeakService(t, udp)

	baseline := takeLeakSample(api, "baseline: one instance, steady state")
	t.Log(baseline)
	if baseline.watches == 0 || baseline.dnsControls != 1 {
		t.Fatalf("fixture did not start one Kubernetes controller: %+v", baseline)
	}
	perController := baseline.watches // informers per controller (services, endpointslices, namespaces).

	// Build the replacement Corefile for this scenario.
	var replacement string
	switch scenario {
	case "failed-late":
		// Port already taken: Listen fails inside startServers, after the
		// Kubernetes startup callback has started the replacement's informers.
		blocked := blockTCPPort(t)
		replacement = good + fmt.Sprintf(".:%d {\n whoami\n}\n", blocked)
	case "failed-early-control":
		// Bad option: the kubernetes plugin's setup fails before any startup callback.
		replacement = fmt.Sprintf(".:0 {\n %s\n}\n", k8sBlock("no_such_option"))
	case "successful-control":
		replacement = good
	}

	var lastErr error
	for i := 1; i <= leakReloadTries; i++ {
		next, err := cur.Restart(NewInput(replacement))
		lastErr = err
		switch scenario {
		case "successful-control":
			if err != nil {
				t.Fatalf("restart %d: %v", i, err)
			}
			cur = next
		default:
			if err == nil {
				t.Fatalf("restart %d unexpectedly succeeded", i)
			}
			if next != cur {
				t.Fatalf("failed restart must return the original instance")
			}
		}
		s := takeLeakSample(api, fmt.Sprintf("after reload attempt %d (%s)", i, scenario))
		t.Log(s)
	}
	if scenario != "successful-control" {
		t.Logf("EVIDENCE restart error: %v", lastErr)
	}

	time.Sleep(3 * time.Second)
	final := takeLeakSample(api, "settled, 3s after the last reload attempt")
	t.Log(final)

	// The live instance must still answer, so these are not simply dead processes.
	udp, _ = CoreDNSServerPorts(cur, 0)
	lookupLeakService(t, udp)

	// Force every watch to drop. Informers that are alive reconnect; the API
	// server sees them come back.
	watchReqsBefore, _ := api.requests()
	api.srv.CloseClientConnections()
	reconnected := waitForWatches(api, final.watches, 30*time.Second)
	after := takeLeakSample(api, "after API dropped all watch connections")
	t.Log(after)
	watchReqsAfter, _ := api.requests()
	t.Logf("EVIDENCE %d/%d watches re-established after a forced disconnect (%d new watch requests issued)",
		reconnected, final.watches, watchReqsAfter-watchReqsBefore)
	if newReqs := watchReqsAfter - watchReqsBefore; newReqs < final.watches {
		t.Errorf("only %d new watch requests after the disconnect, want at least %d", newReqs, final.watches)
	}

	switch scenario {
	case "failed-late":
		want := perController * (1 + leakReloadTries)
		// DEFECT assertions: the live instance is still the original, yet the
		// API server holds a full set of watches per failed attempt.
		if final.watches != want || final.dnsControls != 1+leakReloadTries {
			t.Errorf("leak not reproduced as expected: watches=%d (want %d), controllers=%d (want %d); contract after a fix: %d / 1",
				final.watches, want, final.dnsControls, 1+leakReloadTries, perController)
		}
		if after.watches != want {
			t.Errorf("leaked informers did not reconnect: %d watches, want %d", after.watches, want)
		}
		if final.heapMiB < baseline.heapMiB*1.5 {
			t.Errorf("expected retained informer state in the live heap: baseline %.1f MiB, settled %.1f MiB", baseline.heapMiB, final.heapMiB)
		}
		// Shut the live instance down completely. The leaked informers have no
		// owner, so nothing can stop them; the API server keeps seeing watches.
		shutdownLive()
		time.Sleep(500 * time.Millisecond)
		orphaned, _ := api.active()
		t.Logf("EVIDENCE after full shutdown of the only registered instance, the API server still sees %d open watches (%d leaked controllers)",
			orphaned, leakReloadTries)
		if orphaned != perController*leakReloadTries {
			t.Errorf("orphaned watches = %d, want %d", orphaned, perController*leakReloadTries)
		}
	default:
		// Controls: exactly one controller's worth of watches, flat goroutines.
		if final.watches != perController || final.dnsControls != 1 || after.watches != perController {
			t.Errorf("control scenario %s left extra controllers: watches=%d (want %d), controllers=%d (want 1)",
				scenario, final.watches, perController, final.dnsControls)
		}
		if final.goroutines > baseline.goroutines+10 {
			t.Errorf("goroutines grew in control: baseline %d, settled %d", baseline.goroutines, final.goroutines)
		}
	}
}
