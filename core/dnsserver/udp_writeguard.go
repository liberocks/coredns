package dnsserver

import (
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// defaultMaxPendingUDPWrites bounds, per UDP listener socket, how many response
// writes may be in progress or waiting at once.
//
// miekg/dns serves every UDP datagram in its own goroutine, and all of them
// write their reply through the same socket. The Go runtime serializes those
// writes on one per-descriptor lock that holds at most 2^20-1 holders plus
// waiters; one more terminates the process. If writes stall, every finished
// handler parks in that queue with its request and response still referenced,
// so goroutines and memory grow without limit until the process runs out of
// memory or hits that limit.
//
// The value is far below 2^20-1 and far above what a healthy socket queues, so
// it only acts during a real backlog, where a reply that cannot be written soon
// is worth little: the client retries. It limits the pile-up to a few hundred
// MiB per socket instead of many GiB. The shed plugin gives a tighter bound and
// also stops accepting work; this is the last-resort default for configurations
// without it.
const defaultMaxPendingUDPWrites = 16384

// guardUDPWrites wraps next so that no more than limit writes are pending on
// the socket at once. A write that arrives beyond the limit is dropped, counted
// and reported as written, as UDP gives no delivery guarantee. next may be nil.
func guardUDPWrites(next dns.DecorateWriter, limit int, dropped prometheus.Counter) dns.DecorateWriter {
	g := &udpWriteGuard{limit: int64(limit), dropped: dropped}
	return func(w dns.Writer) dns.Writer {
		if next != nil {
			w = next(w)
		}
		return &guardedWriter{g: g, Writer: w}
	}
}

// udpWriteGuard is the state shared by every response written through one socket.
type udpWriteGuard struct {
	pending atomic.Int64
	limit   int64
	dropped prometheus.Counter
}

type guardedWriter struct {
	g *udpWriteGuard
	dns.Writer
}

// Write implements dns.Writer.
func (w *guardedWriter) Write(p []byte) (int, error) {
	if w.g.pending.Add(1) > w.g.limit {
		w.g.pending.Add(-1)
		w.g.dropped.Inc()
		return len(p), nil
	}
	defer w.g.pending.Add(-1)
	return w.Writer.Write(p)
}
