package webhook

import (
	"net/netip"
	"sync"
	"time"
)

// markedConn identifies a connection the handler marked, and with what.
type markedConn struct {
	src, dst netip.AddrPort
	mark     uint32
}

// recentMarks remembers connections marked in the last ttl, so repeated
// webhooks for the same connection skip the kernel. Transports that
// multiplex (XHTTP, mux) route every sub-request separately, and Xray
// sends a webhook for each, all for one TCP connection whose conntrack
// entry already carries the mark. With a zero ttl it remembers nothing.
type recentMarks struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	marked    map[markedConn]time.Time
	lastSweep time.Time
}

func newRecentMarks(ttl time.Duration) *recentMarks {
	return &recentMarks{ttl: ttl, now: time.Now, marked: make(map[markedConn]time.Time)}
}

// contains reports whether c was marked less than ttl ago.
func (r *recentMarks) contains(c markedConn) bool {
	if r.ttl == 0 {
		return false
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.marked[c]
	return ok && now.Sub(at) < r.ttl
}

// add records that c was just marked, and drops expired entries at most
// once per ttl.
func (r *recentMarks) add(c markedConn) {
	if r.ttl == 0 {
		return
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.marked[c] = now
	if now.Sub(r.lastSweep) < r.ttl {
		return
	}
	for k, at := range r.marked {
		if now.Sub(at) >= r.ttl {
			delete(r.marked, k)
		}
	}
	r.lastSweep = now
}
