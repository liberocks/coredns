package dnsserver_test

// Caddy lifecycle contract for finding 04 ("a failed reload can leave
// Kubernetes informers running").
//
// These tests pin the behavior of the real, pinned github.com/coredns/caddy
// startup and Instance.Restart code that core/dnsserver's OnAbandonedStart
// exists to work around: when a replacement instance has run its startup
// callbacks and a later step fails, Caddy returns the ORIGINAL instance, drops
// the replacement and never runs the replacement's OnShutdown callbacks.
//
// Only two things are fake:
//
//   - a throwaway Caddy server type ("lifecycle-fixture"), so no sockets are
//     opened and no CoreDNS plugins are needed;
//   - a fake controller shaped like the Kubernetes plugin's dnsControl: Run
//     blocks until the stop channel closes, Stop closes it once and returns
//     "shutdown already in progress" the second time.
//
// The "fakek8s" directive registers callbacks the way plugin/kubernetes/setup.go
// did BEFORE the fix: OnStartup runs `go Run()` and waits for readiness, and
// OnShutdown calls Stop. It deliberately does not use OnAbandonedStart, so these
// tests show what Caddy does on its own. If Caddy is ever changed to run a
// discarded replacement's shutdown callbacks, the TestFailedRestartLeaks* tests
// fail, and OnAbandonedStart can be removed.

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
)

const fixtureServerType = "lifecycle-fixture"

// fixtureRegistry holds the fake controllers and an ordered event log. A
// Corefile names its controller, so the same registry can see the original and
// the replacement instance.
type fixtureRegistry struct {
	mu          sync.Mutex
	controllers map[string]*fakeController
	events      []string
}

var fixtures fixtureRegistry

func (r *fixtureRegistry) record(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, fmt.Sprintf(format, args...))
}

func (r *fixtureRegistry) snapshotEvents() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

// reset forgets every controller and event of a previous run with this prefix,
// so the tests stay correct under -count=N (controller names are reused).
func (r *fixtureRegistry) reset(prefix string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.controllers {
		if strings.HasPrefix(name, prefix) {
			delete(r.controllers, name)
		}
	}
	r.events = slices.DeleteFunc(r.events, func(e string) bool { return strings.HasPrefix(e, prefix) })
}

func (r *fixtureRegistry) controller(name string) *fakeController {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.controllers == nil {
		r.controllers = map[string]*fakeController{}
	}
	if c, ok := r.controllers[name]; ok {
		return c
	}
	c := &fakeController{name: name, stopCh: make(chan struct{}), ready: make(chan struct{})}
	r.controllers[name] = c
	return c
}

func (r *fixtureRegistry) running(prefix string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var names []string
	for name, c := range r.controllers {
		if strings.HasPrefix(name, prefix) && c.isRunning() {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

// fakeController mirrors dnsControl's Run/Stop contract.
type fakeController struct {
	name   string
	stopCh chan struct{}
	ready  chan struct{}

	mu       sync.Mutex
	runCalls int
	stopCall int
	running  bool
	stopped  bool
}

func (f *fakeController) Run() {
	f.mu.Lock()
	f.runCalls++
	f.running = true
	f.mu.Unlock()
	fixtures.record("%s:run", f.name)
	close(f.ready) // stands in for "informers have synced".
	<-f.stopCh
	f.mu.Lock()
	f.running = false
	f.mu.Unlock()
	fixtures.record("%s:exited", f.name)
}

func (f *fakeController) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCall++
	fixtures.record("%s:stop", f.name)
	if f.stopped {
		return errors.New("shutdown already in progress")
	}
	close(f.stopCh)
	f.stopped = true
	return nil
}

func (f *fakeController) isRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeController) counts() (runs, stops int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runCalls, f.stopCall
}

// release stops a leaked worker so the test leaves no goroutines behind.
func (f *fakeController) release() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stopped {
		close(f.stopCh)
		f.stopped = true
	}
}

// settle waits (bounded) for the fake worker goroutine to reach the wanted
// state, so assertions never race with the goroutine scheduler.
func (f *fakeController) settle(t *testing.T, wantRunning bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.isRunning() == wantRunning {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// failingServer implements caddy.Server without opening sockets.
type failingServer struct{ failListen bool }

func (s *failingServer) Listen() (net.Listener, error) {
	if s.failListen {
		return nil, errors.New("synthetic listener setup error: address already in use")
	}
	return nil, nil
}
func (s *failingServer) Serve(net.Listener) error                 { return nil }
func (s *failingServer) ListenPacket() (net.PacketConn, error)    { return nil, nil }
func (s *failingServer) ServePacket(net.PacketConn) error         { return nil }
func (s *failingServer) Stop() error                              { return nil }
func (s *failingServer) Address() string                          { return "fixture" }
func (s *failingServer) WrapListener(l net.Listener) net.Listener { return l }

type fixtureContext struct {
	inst       *caddy.Instance
	failListen bool
}

func (c *fixtureContext) InspectServerBlocks(_ string, sb []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	return sb, nil
}

func (c *fixtureContext) MakeServers() ([]caddy.Server, error) {
	c.inst.StorageMu.RLock()
	defer c.inst.StorageMu.RUnlock()
	fail, _ := c.inst.Storage["failListen"].(bool)
	return []caddy.Server{&failingServer{failListen: fail}}, nil
}

func init() {
	caddy.RegisterServerType(fixtureServerType, caddy.ServerType{
		// Directives run in this order, so callbacks are registered in this order.
		Directives: func() []string {
			return []string{"earlyfail", "badsetup", "fakek8s", "latefail", "listen"}
		},
		DefaultInput: func() caddy.Input { return nil },
		NewContext:   func(inst *caddy.Instance) caddy.Context { return &fixtureContext{inst: inst} },
	})

	// earlyfail registers a startup callback that fails BEFORE the fake
	// Kubernetes startup callback runs.
	caddy.RegisterPlugin("earlyfail", caddy.Plugin{ServerType: fixtureServerType, Action: func(c *caddy.Controller) error {
		c.OnStartup(func() error { return errors.New("synthetic early startup callback error") })
		return nil
	}})

	// badsetup fails during directive execution, before any startup callback.
	caddy.RegisterPlugin("badsetup", caddy.Plugin{ServerType: fixtureServerType, Action: func(c *caddy.Controller) error {
		return errors.New("synthetic setup error")
	}})

	// fakek8s is shaped like plugin/kubernetes setup: OnStartup runs the
	// controller and waits for it; OnShutdown stops it. There is deliberately
	// no OnRestartFailed, because the real plugin registers none either.
	caddy.RegisterPlugin("fakek8s", caddy.Plugin{ServerType: fixtureServerType, Action: func(c *caddy.Controller) error {
		c.Next()
		if !c.NextArg() {
			return c.ArgErr()
		}
		name := c.Val()
		ctrl := fixtures.controller(name)
		fixtures.record("%s:setup", name)
		c.OnStartup(func() error {
			fixtures.record("%s:onstart", name)
			go ctrl.Run()
			<-ctrl.ready
			return nil
		})
		c.OnShutdown(func() error {
			fixtures.record("%s:onshutdown", name)
			return ctrl.Stop()
		})
		// A stand-in for plugins that DO register OnRestartFailed (ready,
		// metrics, health, file). It belongs to whichever instance registered
		// it, so for a failed replacement it is the ORIGINAL's list that runs.
		c.OnRestartFailed(func() error {
			fixtures.record("%s:restart-failed-callback", name)
			return nil
		})
		return nil
	}})

	// latefail registers a startup callback that fails AFTER the fake
	// Kubernetes controller has started (a plugin later in plugin.cfg order).
	caddy.RegisterPlugin("latefail", caddy.Plugin{ServerType: fixtureServerType, Action: func(c *caddy.Controller) error {
		c.OnStartup(func() error { return errors.New("synthetic late startup callback error") })
		return nil
	}})

	// listen makes MakeServers return a server whose Listen fails, which is
	// the real shape of "address already in use" on a reload.
	caddy.RegisterPlugin("listen", caddy.Plugin{ServerType: fixtureServerType, Action: func(c *caddy.Controller) error {
		c.Next()
		if c.NextArg() && c.Val() == "fail" {
			c.Set("failListen", true)
		}
		return nil
	}})
}

type fixtureInput struct{ body string }

func (f fixtureInput) ServerType() string { return fixtureServerType }
func (f fixtureInput) Body() []byte       { return []byte(f.body) }
func (f fixtureInput) Path() string       { return "Corefile" }

func corefileFor(name string, extra ...string) fixtureInput {
	lines := append([]string{"fixture {", "  fakek8s " + name}, extra...)
	lines = append(lines, "}")
	return fixtureInput{body: strings.Join(lines, "\n")}
}

// startOriginal starts the original instance and registers teardown that
// releases EVERY fake worker, leaked or not, and stops every instance.
func startOriginal(t *testing.T, prefix string) *caddy.Instance {
	t.Helper()
	caddy.Quiet = true
	fixtures.reset(prefix)
	inst, err := caddy.Start(corefileFor(prefix + "-orig"))
	if err != nil {
		t.Fatalf("start original: %v", err)
	}
	t.Cleanup(func() {
		_ = inst.Stop()
		fixtures.mu.Lock()
		defer fixtures.mu.Unlock()
		for name, c := range fixtures.controllers {
			if strings.HasPrefix(name, prefix) {
				c.release()
			}
		}
	})
	if got := fixtures.running(prefix); !slices.Equal(got, []string{prefix + "-orig"}) {
		t.Fatalf("after start, running controllers = %v, want only the original", got)
	}
	return inst
}

func eventsWithPrefix(prefix string) []string {
	var out []string
	for _, e := range fixtures.snapshotEvents() {
		if strings.HasPrefix(e, prefix) {
			out = append(out, e)
		}
	}
	return out
}

func instanceCount() int { return len(caddy.Instances()) }

// Control: a successful handoff stops the original exactly once and keeps the
// replacement running. This shows the fixture models the real contract.
func TestSuccessfulRestartStopsOriginalOnce(t *testing.T) {
	const p = "lc-success"
	orig := startOriginal(t, p)

	repl, err := orig.Restart(corefileFor(p + "-repl"))
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if repl == orig {
		t.Fatal("successful restart must return a new instance")
	}
	t.Cleanup(func() { _ = repl.Stop() })

	o, r := fixtures.controller(p+"-orig"), fixtures.controller(p+"-repl")
	o.settle(t, false)

	if runs, stops := o.counts(); runs != 1 || stops != 1 {
		t.Errorf("original: run=%d stop=%d, want run=1 stop=1", runs, stops)
	}
	if runs, stops := r.counts(); runs != 1 || stops != 0 {
		t.Errorf("replacement: run=%d stop=%d, want run=1 stop=0", runs, stops)
	}
	if got := fixtures.running(p); !slices.Equal(got, []string{p + "-repl"}) {
		t.Errorf("running controllers = %v, want only the replacement", got)
	}
	if got := eventsWithPrefix(p + "-orig:restart-failed-callback"); len(got) != 0 {
		t.Errorf("OnRestartFailed ran on a successful restart: %v", got)
	}
}

// Control: a replacement that fails before its startup callback never starts a
// worker, so there is nothing to leak. The original is untouched.
func TestFailedRestartBeforeStartupCallbackStartsNothing(t *testing.T) {
	for name, extra := range map[string][]string{
		"setup-error":                    {"badsetup"},
		"earlier-startup-callback-error": {"earlyfail"},
	} {
		t.Run(name, func(t *testing.T) {
			p := "lc-early-" + name
			orig := startOriginal(t, p)

			got, err := orig.Restart(corefileFor(p+"-repl", extra...))
			if err == nil {
				t.Fatal("restart unexpectedly succeeded")
			}
			if got != orig {
				t.Fatal("failed restart must hand back the original instance")
			}
			if runs, stops := fixtures.controller(p + "-repl").counts(); runs != 0 || stops != 0 {
				t.Errorf("replacement: run=%d stop=%d, want run=0 stop=0", runs, stops)
			}
			if runs, stops := fixtures.controller(p + "-orig").counts(); runs != 1 || stops != 0 {
				t.Errorf("original: run=%d stop=%d, want run=1 stop=0", runs, stops)
			}
			if got := fixtures.running(p); !slices.Equal(got, []string{p + "-orig"}) {
				t.Errorf("running controllers = %v, want only the original", got)
			}
			t.Logf("restart error (expected): %v", err)
		})
	}
}

// The defect. The replacement's controller has been started and signalled
// ready; then a later step fails. Caddy returns the ORIGINAL instance, drops the
// replacement from its list, and never runs the replacement's OnShutdown.
func TestFailedRestartLeaksStartedControllerOnLateError(t *testing.T) {
	for name, extra := range map[string][]string{
		"listener-setup-error":         {"listen fail"},
		"later-startup-callback-error": {"latefail"},
	} {
		t.Run(name, func(t *testing.T) {
			p := "lc-late-" + name
			orig := startOriginal(t, p)
			before := instanceCount()

			got, err := orig.Restart(corefileFor(p+"-repl", extra...))
			if err == nil {
				t.Fatal("restart unexpectedly succeeded")
			}
			t.Logf("restart error (expected): %v", err)
			if got != orig {
				t.Fatal("failed restart must hand back the original instance")
			}

			repl := fixtures.controller(p + "-repl")
			runs, stops := repl.counts()

			// Preconditions proving the replacement really got that far.
			if runs != 1 {
				t.Fatalf("replacement run calls = %d, want 1 (fixture did not reach the late error)", runs)
			}
			if inst := instanceCount(); inst != before {
				t.Errorf("caddy instance list = %d entries, want %d: the failed replacement must be removed", inst, before)
			}

			// DEFECT assertions: replacement was started but never stopped.
			if stops != 0 {
				t.Errorf("replacement stop calls = %d; the leak is no longer reproduced (want 0 today, 1 once fixed)", stops)
			}
			if !repl.isRunning() {
				t.Errorf("replacement worker has exited; the leak is no longer reproduced")
			}
			if ev := eventsWithPrefix(p + "-repl:onshutdown"); len(ev) != 0 {
				t.Errorf("replacement OnShutdown ran: %v", ev)
			}

			// The original is untouched and still running.
			if runs, stops := fixtures.controller(p + "-orig").counts(); runs != 1 || stops != 0 {
				t.Errorf("original: run=%d stop=%d, want run=1 stop=0", runs, stops)
			}

			// Callback ownership: the failure path ran the ORIGINAL's
			// OnRestartFailed callbacks, which have no reach into the
			// replacement's controller.
			if ev := eventsWithPrefix(p + "-orig:restart-failed-callback"); len(ev) != 1 {
				t.Errorf("original's OnRestartFailed ran %d times, want 1", len(ev))
			}
			if ev := eventsWithPrefix(p + "-repl:restart-failed-callback"); len(ev) != 0 {
				t.Errorf("replacement's OnRestartFailed ran: %v", ev)
			}

			// Two controllers are live, but only one instance is registered.
			// Contract (once fixed): exactly [orig].
			if got := fixtures.running(p); !slices.Equal(got, []string{p + "-orig", p + "-repl"}) {
				t.Errorf("running controllers = %v, want [orig repl] while the defect exists", got)
			}

			t.Logf("event timeline:\n  %s", strings.Join(eventsWithPrefix(p), "\n  "))
		})
	}
}

// The leak is cumulative and survives a later successful reload: the reload
// plugin keeps retrying on every Corefile change, and each failed attempt
// leaves one more worker behind.
func TestFailedRestartLeaksAccumulateAcrossAttempts(t *testing.T) {
	const p = "lc-accum"
	const failures = 5
	orig := startOriginal(t, p)

	for i := 0; i < failures; i++ {
		_, err := orig.Restart(corefileFor(fmt.Sprintf("%s-fail%d", p, i), "listen fail"))
		if err == nil {
			t.Fatalf("attempt %d unexpectedly succeeded", i)
		}
	}
	// 1 original + N failed replacements, with only the original registered.
	if got := fixtures.running(p); len(got) != 1+failures {
		t.Fatalf("after %d failed reloads running controllers = %v, want %d (contract: 1)", failures, got, 1+failures)
	}
	t.Logf("after %d failed reloads: %d controllers running, %d caddy instance(s) registered for this fixture",
		failures, len(fixtures.running(p)), instanceCount())

	// Operator fixes the Corefile; the next reload succeeds.
	repl, err := orig.Restart(corefileFor(p + "-fixed"))
	if err != nil {
		t.Fatalf("successful restart: %v", err)
	}
	t.Cleanup(func() { _ = repl.Stop() })
	fixtures.controller(p+"-orig").settle(t, false)

	got := fixtures.running(p)
	// Contract (once fixed): [fixed] only. Today the original is stopped but
	// every failed replacement is still running.
	if len(got) != 1+failures {
		t.Errorf("after the later successful reload running controllers = %v, want %d while the defect exists (contract: 1)", got, 1+failures)
	}
	for i := 0; i < failures; i++ {
		if !slices.Contains(got, fmt.Sprintf("%s-fail%d", p, i)) {
			t.Errorf("failed attempt %d was cleaned up; the leak is no longer reproduced", i)
		}
	}
	t.Logf("after the later successful reload: running=%v", got)
}
