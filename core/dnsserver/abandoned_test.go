package dnsserver_test

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/whoami"
)

// abandonWorker stands in for a controller that a startup callback starts and
// OnShutdown stops. Its Stop has the same contract as the Kubernetes
// controller's: closing the stop channel once, then reporting an error.
type abandonWorker struct {
	stopCh chan struct{}

	mu        sync.Mutex
	started   int
	stopCalls int
	running   bool
	stopped   bool
}

func (w *abandonWorker) start() {
	ready := make(chan struct{})
	go func() {
		w.mu.Lock()
		w.started++
		w.running = true
		w.mu.Unlock()
		close(ready)
		<-w.stopCh
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
	}()
	<-ready
}

func (w *abandonWorker) stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopCalls++
	if w.stopped {
		return errors.New("shutdown already in progress")
	}
	close(w.stopCh)
	w.stopped = true
	return nil
}

// release stops the worker without counting a Stop call, for test teardown.
func (w *abandonWorker) release() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.stopped {
		close(w.stopCh)
		w.stopped = true
	}
}

func (w *abandonWorker) counts() (started, stopCalls int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.started, w.stopCalls
}

// reaches waits briefly for the worker goroutine to be (or not be) running and
// reports whether it reached the wanted state.
func (w *abandonWorker) reaches(wantRunning bool) bool {
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
		w.mu.Lock()
		running := w.running
		w.mu.Unlock()
		if running == wantRunning {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
	}
}

var (
	abandonWorkers   sync.Map // name -> *abandonWorker
	abandonSeq       atomic.Int64
	registerAbandons sync.Once
)

func abandonWorkerFor(name string) *abandonWorker {
	w, _ := abandonWorkers.LoadOrStore(name, &abandonWorker{stopCh: make(chan struct{})})
	return w.(*abandonWorker)
}

// setupTestAbandon mirrors plugin/kubernetes/setup.go: OnAbandonedStart is
// registered before the startup callback that starts the work.
func setupTestAbandon(c *caddy.Controller) error {
	c.Next()
	if !c.NextArg() {
		return c.ArgErr()
	}
	w := abandonWorkerFor(c.Val())
	dnsserver.OnAbandonedStart(c, func() error { _ = w.stop(); return nil })
	c.OnStartup(func() error { w.start(); return nil })
	c.OnShutdown(w.stop)
	return nil
}

func configureAbandonTests(t *testing.T) {
	t.Helper()
	oldDirectives, oldCaddyQuiet, oldDNSQuiet := dnsserver.Directives, caddy.Quiet, dnsserver.Quiet
	t.Cleanup(func() {
		dnsserver.Directives, caddy.Quiet, dnsserver.Quiet = oldDirectives, oldCaddyQuiet, oldDNSQuiet
	})
	// test_earlyfail runs before test_abandon and test_latefail after it.
	if err := dnsserver.SetDirectives([]string{"bind", "test_earlyfail", "test_badshutdown", "test_abandon", "test_latefail", "whoami"}); err != nil {
		t.Fatal(err)
	}
	registerAbandons.Do(func() {
		plugin.Register("test_abandon", setupTestAbandon)
		plugin.Register("test_earlyfail", func(c *caddy.Controller) error {
			c.OnStartup(func() error { return errors.New("synthetic early startup error") })
			return nil
		})
		plugin.Register("test_latefail", func(c *caddy.Controller) error {
			c.OnStartup(func() error { return errors.New("synthetic late startup error") })
			return nil
		})
		plugin.Register("test_badshutdown", func(c *caddy.Controller) error {
			c.OnShutdown(func() error { return errors.New("synthetic shutdown error") })
			return nil
		})
	})
	caddy.Quiet, dnsserver.Quiet = true, true
}

func abandonInput(corefile string) caddy.Input {
	return caddy.CaddyfileInput{Filepath: "Corefile", Contents: []byte(corefile), ServerTypeName: "dns"}
}

// abandonCorefile returns a Corefile with one worker-owning block. Extra
// directives go into that block, and extraBlocks are appended after it.
func abandonCorefile(name, extraDirectives, extraBlocks string) caddy.Input {
	return abandonInput(fmt.Sprintf(".:0 {\n bind 127.0.0.1\n test_abandon %s\n %s\n whoami\n}\n%s", name, extraDirectives, extraBlocks))
}

// blockedBlock is a server block whose TCP port is taken, so that Listen fails
// inside startServers, after every startup callback has run.
func blockedBlock(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return fmt.Sprintf(".:%d {\n bind 127.0.0.1\n whoami\n}\n", ln.Addr().(*net.TCPAddr).Port)
}

// startAbandonOriginal starts the original instance and registers teardown that
// shuts down every instance this test created, including ones a test can only
// find through caddy.Instances(), and releases every worker.
func startAbandonOriginal(t *testing.T, name, extraDirectives string) (*caddy.Instance, string) {
	t.Helper()
	configureAbandonTests(t)
	before := slices.Clone(caddy.Instances())
	name = fmt.Sprintf("%s%d", name, abandonSeq.Add(1))
	orig, err := caddy.Start(abandonCorefile(name+"-orig", extraDirectives, ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, inst := range slices.Clone(caddy.Instances()) {
			if !slices.Contains(before, inst) {
				// Only run the callbacks that can still do work; errors from
				// already-stopped workers are expected here.
				_ = inst.ShutdownCallbacks()
				_ = inst.Stop()
			}
		}
		abandonWorkers.Range(func(k, v any) bool {
			if strings.HasPrefix(k.(string), name) {
				v.(*abandonWorker).release()
			}
			return true
		})
	})
	return orig, name
}

func wantWorker(t *testing.T, name string, running bool, started, stopCalls int) {
	t.Helper()
	w := abandonWorkerFor(name)
	if !w.reaches(running) {
		t.Errorf("%s: running = %v, want %v", name, !running, running)
	}
	if s, c := w.counts(); s != started || c != stopCalls {
		t.Errorf("%s: started=%d stop calls=%d, want started=%d stop calls=%d", name, s, c, started, stopCalls)
	}
}

// Control: a successful handoff stops the original once and leaves the
// replacement running; the abandoned-start path must not fire.
func TestAbandonedStartNotRunOnSuccessfulRestart(t *testing.T) {
	orig, name := startAbandonOriginal(t, "ok", "")
	repl, err := orig.Restart(abandonCorefile(name+"-repl", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	if repl == orig {
		t.Fatal("successful restart must return a new instance")
	}
	wantWorker(t, name+"-orig", false, 1, 1)
	wantWorker(t, name+"-repl", true, 1, 0)
}

// A failure before the worker's startup callback starts nothing. There is
// nothing to clean up, and the original is untouched.
func TestAbandonedStartNotRunBeforeWorkerStarts(t *testing.T) {
	orig, name := startAbandonOriginal(t, "early", "")
	got, err := orig.Restart(abandonCorefile(name+"-repl", "test_earlyfail", ""))
	if err == nil || got != orig {
		t.Fatalf("restart = (%v, %v), want the original and an error", got == orig, err)
	}
	wantWorker(t, name+"-repl", false, 0, 0)
	wantWorker(t, name+"-orig", true, 1, 0)
}

// The defect: the replacement's worker started and a later step failed. The
// worker must be stopped exactly once and the original must keep running.
func TestAbandonedStartStopsWorkerOnLateFailure(t *testing.T) {
	for _, tc := range []struct {
		name            string
		extraDirectives string
		blocked         bool
	}{
		{"listener-error", "", true},
		{"later-startup-callback-error", "test_latefail", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orig, name := startAbandonOriginal(t, "late", "")
			extraBlocks := ""
			if tc.blocked {
				extraBlocks = blockedBlock(t)
			}
			instancesBefore := len(caddy.Instances())

			got, err := orig.Restart(abandonCorefile(name+"-repl", tc.extraDirectives, extraBlocks))
			if err == nil || got != orig {
				t.Fatalf("restart = (%v, %v), want the original and an error", got == orig, err)
			}
			t.Logf("restart error (expected): %v", err)
			if n := len(caddy.Instances()); n != instancesBefore {
				t.Errorf("instance list has %d entries, want %d", n, instancesBefore)
			}
			wantWorker(t, name+"-repl", false, 1, 1)
			wantWorker(t, name+"-orig", true, 1, 0)
		})
	}
}

// Every failed attempt is cleaned up, and a later successful reload leaves only
// the new instance's worker running.
func TestAbandonedStartRepeatedFailures(t *testing.T) {
	const failures = 5
	orig, name := startAbandonOriginal(t, "repeat", "")
	blocked := blockedBlock(t)
	for i := range failures {
		if _, err := orig.Restart(abandonCorefile(fmt.Sprintf("%s-fail%d", name, i), "", blocked)); err == nil {
			t.Fatalf("attempt %d unexpectedly succeeded", i)
		}
	}
	for i := range failures {
		wantWorker(t, fmt.Sprintf("%s-fail%d", name, i), false, 1, 1)
	}
	wantWorker(t, name+"-orig", true, 1, 0)

	repl, err := orig.Restart(abandonCorefile(name+"-fixed", "", ""))
	if err != nil {
		t.Fatal(err)
	}
	_ = repl
	wantWorker(t, name+"-orig", false, 1, 1)
	wantWorker(t, name+"-fixed", true, 1, 0)
	for i := range failures {
		// No second stop: the abandoned workers were already cleaned up.
		wantWorker(t, fmt.Sprintf("%s-fail%d", name, i), false, 1, 1)
	}
}

// Restart can report an error after the replacement is already serving: when an
// original shutdown callback fails, Caddy returns the original and runs its
// OnRestartFailed callbacks, but the replacement is registered and live. It must
// not be stopped.
func TestAbandonedStartLeavesLiveReplacementAlone(t *testing.T) {
	orig, name := startAbandonOriginal(t, "live", "test_badshutdown")
	got, err := orig.Restart(abandonCorefile(name+"-repl", "", ""))
	if err == nil || got != orig {
		t.Fatalf("restart = (%v, %v), want the original and a shutdown error", got == orig, err)
	}
	t.Logf("restart error (expected): %v", err)
	wantWorker(t, name+"-repl", true, 1, 0)
}
