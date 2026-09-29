package tcshape

import (
	"errors"
	"slices"
	"testing"
	"time"
)

type fakeLister struct {
	classes []Class
	err     error
}

func (f *fakeLister) Classes() ([]Class, error) { return f.classes, f.err }

type fakeDeleter struct {
	deleted []uint32
	err     error
}

func (f *fakeDeleter) Delete(mark uint32) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, mark)
	return nil
}

func newTestCollector(l *fakeLister, d *fakeDeleter) (*IdleCollector, *time.Time) {
	now := time.Unix(1_000_000, 0)
	c := NewIdleCollector(l, d, time.Hour, nil)
	c.now = func() time.Time { return now }
	return c, &now
}

func TestIdleCollectorDeletesOnlyIdleClasses(t *testing.T) {
	l := &fakeLister{classes: []Class{{Mark: 0x10002, Bytes: 100}, {Mark: 0x10003, Bytes: 100}}}
	d := &fakeDeleter{}
	c, now := newTestCollector(l, d)

	c.Collect() // first sighting starts both idle periods
	*now = now.Add(30 * time.Minute)
	l.classes[1].Bytes = 500 // 0x10003 is active
	c.Collect()
	*now = now.Add(31 * time.Minute)
	c.Collect()

	if !slices.Equal(d.deleted, []uint32{0x10002}) {
		t.Fatalf("after 61 idle minutes: deleted %#x; want only 0x10002", d.deleted)
	}

	// 0x10003 went idle at +30m, so it goes at +90m, not before.
	*now = now.Add(28 * time.Minute)
	c.Collect()
	if len(d.deleted) != 1 {
		t.Fatalf("0x10003 deleted before its idle period ended: %#x", d.deleted)
	}
	*now = now.Add(2 * time.Minute)
	c.Collect()
	if !slices.Equal(d.deleted, []uint32{0x10002, 0x10003}) {
		t.Fatalf("deleted %#x, want 0x10002 then 0x10003", d.deleted)
	}
}

func TestIdleCollectorKeepsClassOnDeleteError(t *testing.T) {
	l := &fakeLister{classes: []Class{{Mark: 0x10002}}}
	d := &fakeDeleter{err: errors.New("tc failed")}
	c, now := newTestCollector(l, d)

	c.Collect()
	*now = now.Add(2 * time.Hour)
	c.Collect()

	d.err = nil
	c.Collect()
	if !slices.Equal(d.deleted, []uint32{0x10002}) {
		t.Fatalf("expected the delete to be retried on the next pass, got %#x", d.deleted)
	}
}

func TestIdleCollectorRestartsIdlePeriodForRecreatedClass(t *testing.T) {
	l := &fakeLister{classes: []Class{{Mark: 0x10002, Bytes: 100}}}
	d := &fakeDeleter{}
	c, now := newTestCollector(l, d)

	c.Collect()
	l.classes = nil // deleted by someone else, e.g. DELETE /marks
	*now = now.Add(50 * time.Minute)
	c.Collect()
	l.classes = []Class{{Mark: 0x10002, Bytes: 100}} // recreated with the same byte count
	*now = now.Add(20 * time.Minute)
	c.Collect()
	if len(d.deleted) != 0 {
		t.Fatalf("a recreated class must get a fresh idle period, got deleted %#x", d.deleted)
	}
}
