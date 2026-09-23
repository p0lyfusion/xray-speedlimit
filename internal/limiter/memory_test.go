package limiter_test

import (
	"sync"
	"testing"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

func TestMemoryStoreSetListDelete(t *testing.T) {
	s := limiter.NewMemoryStore()

	if err := s.Set(42, 1000); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Set(43, 2000); err != nil {
		t.Fatalf("Set: %v", err)
	}

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("List returned %d entries, want 2", len(entries))
	}

	if err := s.Delete(42); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	entries, err = s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Mark != 43 || entries[0].RateBytesPerSec != 2000 {
		t.Fatalf("unexpected entries after delete: %+v", entries)
	}
}

func TestMemoryStoreDeleteMissingIsNoop(t *testing.T) {
	s := limiter.NewMemoryStore()
	if err := s.Delete(999); err != nil {
		t.Fatalf("Delete of missing mark should not error: %v", err)
	}
}

func TestMemoryStoreConcurrent(t *testing.T) {
	s := limiter.NewMemoryStore()
	var wg sync.WaitGroup
	for i := uint32(0); i < 200; i++ {
		wg.Add(1)
		go func(mark uint32) {
			defer wg.Done()
			_ = s.Set(mark, mark*10)
		}(i)
	}
	wg.Wait()

	entries, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 200 {
		t.Fatalf("List returned %d entries, want 200", len(entries))
	}
}
