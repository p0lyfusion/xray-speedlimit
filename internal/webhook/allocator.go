// Package webhook implements the HTTP receiver for xray-core's
// app/router WebhookNotifier, allocating a stable per-email mark and
// applying it to the client's conntrack entry.
package webhook

import (
	"log/slog"
	"maps"
	"sync"
)

// Allocator hands out a stable, unique mark per email from a fixed-size
// pool. It never issues mark 0, which callers must treat as "no mark".
type Allocator struct {
	mu        sync.Mutex
	base      uint32
	count     uint32
	next      uint32
	marks     map[string]uint32
	exhausted bool
	log       *slog.Logger
}

// NewAllocator creates an Allocator issuing marks in [base, base+count).
func NewAllocator(base, count uint32, log *slog.Logger) *Allocator {
	if log == nil {
		log = slog.Default()
	}
	return &Allocator{
		base:  base,
		count: count,
		marks: make(map[string]uint32),
		log:   log,
	}
}

// Allocate returns the mark assigned to email, allocating a new one on
// first use. isNew reports whether this call is what allocated it, so
// callers can do first-time-only setup (e.g. provisioning a rate) without
// repeating it on every subsequent call for the same email. Allocate
// returns mark 0 if the pool is exhausted or email is empty; callers must
// treat 0 as "do not set a mark" and ignore isNew in that case.
func (a *Allocator) Allocate(email string) (mark uint32, isNew bool) {
	if email == "" {
		return 0, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if mark, ok := a.marks[email]; ok {
		return mark, false
	}

	for a.next < a.count {
		mark := a.base + a.next
		a.next++
		if mark == 0 {
			continue
		}
		a.marks[email] = mark
		return mark, true
	}

	if !a.exhausted {
		a.exhausted = true
		a.log.Warn("mark range exhausted, continuing without new marks", "first", a.base, "last", a.base+a.count-1)
	}
	return 0, false
}

// Marks returns a copy of the current email -> mark assignments.
func (a *Allocator) Marks() map[string]uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return maps.Clone(a.marks)
}
