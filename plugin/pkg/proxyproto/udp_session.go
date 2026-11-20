package proxyproto

import (
	"container/list"
	"net"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

// udpSessionMaxEntries is the default maximum number of concurrent UDP
// sessions that the LRU cache will track. When the cache is full the
// least-recently-used entry is evicted.
const udpSessionMaxEntries = 10_240

// sessionInitMu serializes lazy initialization of PacketConn.sessionCache.
var sessionInitMu sync.Mutex

// sessionTable is a fixed-capacity LRU of UDP sessions whose entries expire
// after a fixed TTL.
//
// It deliberately owns no goroutine and no timer. A cache that needs a
// background worker to expire entries outlives the PacketConn that created it
// unless somebody stops the worker, and the PacketConn is closed by the DNS
// server, which has no hook for that. Expiry is instead applied on access.
// Because every entry has the same TTL and is refreshed on use, the entry at the
// back of the list is always the first to expire, so sweeping from the back is
// exact. Entries that are never touched again stay in memory until they are
// evicted by capacity or the table is garbage collected with its PacketConn;
// the table never holds more than limit entries.
type sessionTable struct {
	mu    sync.Mutex
	limit int
	ttl   time.Duration
	order *list.List // front is most recently used
	items map[string]*list.Element
}

type sessionEntry struct {
	key     string
	header  *proxyproto.Header
	expires time.Time
}

func newSessionTable(limit int, ttl time.Duration) *sessionTable {
	return &sessionTable{limit: limit, ttl: ttl, order: list.New(), items: make(map[string]*list.Element)}
}

// sweep removes expired entries from the back. The caller must hold t.mu.
func (t *sessionTable) sweep(now time.Time) {
	for e := t.order.Back(); e != nil; e = t.order.Back() {
		if !now.After(e.Value.(*sessionEntry).expires) {
			return
		}
		t.remove(e)
	}
}

// remove deletes e. The caller must hold t.mu.
func (t *sessionTable) remove(e *list.Element) {
	t.order.Remove(e)
	delete(t.items, e.Value.(*sessionEntry).key)
}

// add inserts or refreshes key. Refreshing resets the TTL.
func (t *sessionTable) add(key string, header *proxyproto.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.sweep(now)
	expires := now.Add(t.ttl)
	if e, ok := t.items[key]; ok {
		ent := e.Value.(*sessionEntry)
		ent.header, ent.expires = header, expires
		t.order.MoveToFront(e)
		return
	}
	t.items[key] = t.order.PushFront(&sessionEntry{key: key, header: header, expires: expires})
	for t.limit > 0 && t.order.Len() > t.limit {
		t.remove(t.order.Back())
	}
}

// get returns the header for key if present and unexpired, and refreshes its TTL.
func (t *sessionTable) get(key string) (*proxyproto.Header, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.sweep(now)
	e, ok := t.items[key]
	if !ok {
		return nil, false
	}
	ent := e.Value.(*sessionEntry)
	ent.expires = now.Add(t.ttl)
	t.order.MoveToFront(e)
	return ent.header, true
}

// Len returns the number of unexpired sessions.
func (t *sessionTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweep(time.Now())
	return t.order.Len()
}

// ensureSessionCache lazily creates the session table if it hasn't been
// created yet. The table itself is thread-safe once constructed.
func (c *PacketConn) ensureSessionCache() {
	if c.sessionCache != nil {
		return
	}
	sessionInitMu.Lock()
	defer sessionInitMu.Unlock()
	if c.sessionCache != nil {
		return // double-check after acquiring lock
	}
	cap := c.UDPSessionTrackingMaxSessions
	if cap <= 0 {
		cap = udpSessionMaxEntries
	}
	c.sessionCache = newSessionTable(cap, c.UDPSessionTrackingTTL)
}

// storeSession inserts or refreshes the session entry for remoteAddr.
// Calling add on an existing key resets its TTL.
func (c *PacketConn) storeSession(remoteAddr net.Addr, header *proxyproto.Header) {
	c.ensureSessionCache()
	c.sessionCache.add(sessionKey(remoteAddr), header)
}

// lookupSession returns the cached source address for remoteAddr, if one
// exists and has not expired. Looking up a key refreshes its TTL.
func (c *PacketConn) lookupSession(remoteAddr net.Addr) (*proxyproto.Header, bool) {
	if c.sessionCache == nil {
		return nil, false
	}
	return c.sessionCache.get(sessionKey(remoteAddr))
}

func sessionKey(addr net.Addr) string {
	return addr.Network() + "://" + addr.String()
}
