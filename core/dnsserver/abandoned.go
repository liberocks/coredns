package dnsserver

import (
	"errors"
	"slices"
	"sync"

	"github.com/coredns/caddy"
)

// When a reload fails after the replacement instance has run its startup
// callbacks (for example because a new listener cannot be bound), Caddy removes
// the replacement from its instance list, returns the original instance and
// never runs the replacement's OnShutdown callbacks. Anything the replacement's
// startup callbacks started, such as the Kubernetes informers, keeps running
// with nothing left that can stop it.
//
// The original instance's OnRestartFailed callbacks do run, so every dns
// instance gets one that stops the work of replacements that were abandoned this
// way. Which replacement was abandoned is decided by liveness, not by who
// registered what: a start is abandoned when its startup callbacks have begun
// and its instance is no longer in Caddy's instance list. An instance that is
// still starting, or that is already running, is never touched.

// abandonedKey is the Instance.Storage key for an instance's *abandonedStart.
type abandonedKey struct{}

// abandonedStart holds the cleanup functions registered for one instance.
type abandonedStart struct {
	mu  sync.Mutex
	fns []func() error
}

// armedStarts is every abandonedStart whose instance has begun its startup
// callbacks and has not been shut down.
var armedStarts = struct {
	sync.Mutex
	set map[*abandonedStart]struct{}
}{set: make(map[*abandonedStart]struct{})}

func (a *abandonedStart) arm() {
	armedStarts.Lock()
	armedStarts.set[a] = struct{}{}
	armedStarts.Unlock()
}

func (a *abandonedStart) disarm() {
	armedStarts.Lock()
	delete(armedStarts.set, a)
	armedStarts.Unlock()
}

// OnAbandonedStart registers fn to run if the instance c belongs to is discarded
// by a failed reload after its startup callbacks have started. It is for work
// that a startup callback starts and that OnShutdown would normally stop, since
// Caddy does not run OnShutdown for a discarded replacement.
//
// Call it before the c.OnStartup that starts the work, so the start is known
// before the work begins. fn may also run when the startup callbacks failed
// before the work started, so it must be safe in that case. It runs at most once
// and never for an instance that started successfully, but it can run alongside
// the normal shutdown path of a different instance that is being stopped at the
// same moment, so it should tolerate being run after OnShutdown, and report no
// error for that.
func OnAbandonedStart(c *caddy.Controller, fn func() error) {
	a, ok := c.Get(abandonedKey{}).(*abandonedStart)
	if !ok {
		a = &abandonedStart{}
		c.Set(abandonedKey{}, a)
		c.OnStartup(func() error { a.arm(); return nil })
		c.OnShutdown(func() error { a.disarm(); return nil })
	}
	a.mu.Lock()
	a.fns = append(a.fns, fn)
	a.mu.Unlock()
}

// stopAbandonedStarts runs the cleanup functions of every armed start whose
// instance is no longer in Caddy's instance list. It is registered as an
// OnRestartFailed callback of every dns instance.
func stopAbandonedStarts() error {
	live := make(map[*abandonedStart]struct{})
	for _, inst := range caddy.Instances() {
		inst.StorageMu.RLock()
		if a, ok := inst.Storage[abandonedKey{}].(*abandonedStart); ok {
			live[a] = struct{}{}
		}
		inst.StorageMu.RUnlock()
	}

	var abandoned []*abandonedStart
	armedStarts.Lock()
	for a := range armedStarts.set {
		if _, ok := live[a]; !ok {
			abandoned = append(abandoned, a)
			delete(armedStarts.set, a)
		}
	}
	armedStarts.Unlock()

	var errs []error
	for _, a := range abandoned {
		a.mu.Lock()
		fns := slices.Clone(a.fns)
		a.mu.Unlock()
		for _, fn := range fns {
			if err := fn(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
