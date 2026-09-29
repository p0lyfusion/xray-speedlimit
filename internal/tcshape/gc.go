package tcshape

import (
	"log/slog"
	"time"
)

// ClassLister lists the per-user classes on an interface. *Shaper
// satisfies it.
type ClassLister interface {
	Classes() ([]Class, error)
}

// ClassDeleter deletes a mark's class and its record in the store. The
// Store WrapStore returns satisfies it; with the record gone, the webhook
// handler provisions the mark again on its next webhook.
type ClassDeleter interface {
	Delete(mark uint32) error
}

type classSeen struct {
	bytes uint64
	since time.Time
}

// IdleCollector deletes per-user classes that have sent nothing for a
// while. Marks come from hashing emails, so without it every email ever
// seen would keep a class in the kernel for good.
//
// A class counts as idle once its byte counter hasn't moved for the idle
// period, as observed by successive Collect calls. Counting starts at the
// first Collect that sees the class, so a restart gives every class a
// fresh idle period. A deleted class's user gets a new one on their next
// webhook, and a rate set by hand through the API is lost with it.
type IdleCollector struct {
	lister  ClassLister
	deleter ClassDeleter
	idle    time.Duration
	log     *slog.Logger
	now     func() time.Time

	seen map[uint32]classSeen
}

// NewIdleCollector creates an IdleCollector.
func NewIdleCollector(lister ClassLister, deleter ClassDeleter, idle time.Duration, log *slog.Logger) *IdleCollector {
	if log == nil {
		log = slog.Default()
	}
	return &IdleCollector{
		lister:  lister,
		deleter: deleter,
		idle:    idle,
		log:     log,
		now:     time.Now,
		seen:    make(map[uint32]classSeen),
	}
}

// Collect takes one look at the classes and deletes those that have been
// idle long enough. It is not safe for concurrent use.
func (c *IdleCollector) Collect() {
	classes, err := c.lister.Classes()
	if err != nil {
		c.log.Error("idle class collection: listing classes", "error", err)
		return
	}

	now := c.now()
	present := make(map[uint32]bool, len(classes))
	deleted := 0
	for _, cl := range classes {
		present[cl.Mark] = true
		prev, ok := c.seen[cl.Mark]
		if !ok || prev.bytes != cl.Bytes {
			c.seen[cl.Mark] = classSeen{bytes: cl.Bytes, since: now}
			continue
		}
		if now.Sub(prev.since) < c.idle {
			continue
		}
		if err := c.deleter.Delete(cl.Mark); err != nil {
			c.log.Error("idle class collection: deleting class", "mark", cl.Mark, "error", err)
			continue
		}
		delete(c.seen, cl.Mark)
		deleted++
	}
	for m := range c.seen {
		if !present[m] {
			delete(c.seen, m)
		}
	}
	if deleted > 0 {
		c.log.Info("deleted idle per-user classes", "count", deleted, "remaining", len(classes)-deleted)
	}
}
