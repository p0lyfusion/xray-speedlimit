package tcshape

import (
	"errors"
	"testing"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

type fakeShaper struct {
	rates   map[uint32]uint32
	removed []uint32
	setErr  error
	delErr  error
}

func newFakeShaper() *fakeShaper {
	return &fakeShaper{rates: make(map[uint32]uint32)}
}

func (f *fakeShaper) SetRate(mark uint32, rate uint32) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.rates[mark] = rate
	return nil
}

func (f *fakeShaper) Remove(mark uint32) error {
	if f.delErr != nil {
		return f.delErr
	}
	f.removed = append(f.removed, mark)
	delete(f.rates, mark)
	return nil
}

type fakeBaseStore struct {
	entries map[uint32]uint32
}

func newFakeBaseStore() *fakeBaseStore {
	return &fakeBaseStore{entries: make(map[uint32]uint32)}
}

func (f *fakeBaseStore) Set(mark, rate uint32) error {
	f.entries[mark] = rate
	return nil
}

func (f *fakeBaseStore) Delete(mark uint32) error {
	delete(f.entries, mark)
	return nil
}

func (f *fakeBaseStore) List() ([]limiter.Entry, error) {
	entries := make([]limiter.Entry, 0, len(f.entries))
	for mark, rate := range f.entries {
		entries = append(entries, limiter.Entry{Mark: mark, RateBytesPerSec: rate})
	}
	return entries, nil
}

func TestWrapStoreSetAppliesShaping(t *testing.T) {
	base := newFakeBaseStore()
	shaper := newFakeShaper()
	store := WrapStore(base, shaper, nil)

	if err := store.Set(42, 1_000_000); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if base.entries[42] != 1_000_000 {
		t.Fatalf("base store not updated: %+v", base.entries)
	}
	if shaper.rates[42] != 1_000_000 {
		t.Fatalf("shaper not updated: %+v", shaper.rates)
	}
}

func TestWrapStoreSetPropagatesShaperError(t *testing.T) {
	base := newFakeBaseStore()
	shaper := newFakeShaper()
	shaper.setErr = errors.New("tc failed")
	store := WrapStore(base, shaper, nil)

	if err := store.Set(1, 1); err == nil {
		t.Fatal("expected error from shaper to propagate")
	}
}

func TestWrapStoreDeleteRemovesShaping(t *testing.T) {
	base := newFakeBaseStore()
	shaper := newFakeShaper()
	store := WrapStore(base, shaper, nil)

	_ = store.Set(7, 500)
	if err := store.Delete(7); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := base.entries[7]; ok {
		t.Fatal("base store entry not deleted")
	}
	if len(shaper.removed) != 1 || shaper.removed[0] != 7 {
		t.Fatalf("expected shaper.Remove(7), got %+v", shaper.removed)
	}
}

func TestWrapStoreListDelegates(t *testing.T) {
	base := newFakeBaseStore()
	_ = base.Set(1, 100)
	store := WrapStore(base, newFakeShaper(), nil)

	entries, err := store.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Mark != 1 || entries[0].RateBytesPerSec != 100 {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}
