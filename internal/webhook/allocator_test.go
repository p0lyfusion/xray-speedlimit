package webhook

import (
	"sync"
	"testing"
)

func TestAllocatorUniqueAndStable(t *testing.T) {
	a := NewAllocator(1000, 10, nil)

	mark1, isNew1 := a.Allocate("user-a")
	mark2, isNew2 := a.Allocate("user-b")

	if mark1 == 0 || mark2 == 0 {
		t.Fatalf("expected non-zero marks, got %d and %d", mark1, mark2)
	}
	if mark1 == mark2 {
		t.Fatalf("expected different marks for different emails, got %d for both", mark1)
	}
	if !isNew1 || !isNew2 {
		t.Fatalf("expected isNew on first allocation, got %v and %v", isNew1, isNew2)
	}
	if again, isNew := a.Allocate("user-a"); again != mark1 || isNew {
		t.Fatalf("expected stable mark %d with isNew=false, got %d isNew=%v", mark1, again, isNew)
	}
}

func TestAllocatorEmptyEmail(t *testing.T) {
	a := NewAllocator(1, 5, nil)
	if mark, isNew := a.Allocate(""); mark != 0 || isNew {
		t.Fatalf("expected 0/false for empty email, got %d/%v", mark, isNew)
	}
}

func TestAllocatorNeverReturnsZero(t *testing.T) {
	a := NewAllocator(0, 5, nil)
	for i := 0; i < 4; i++ {
		if mark, isNew := a.Allocate(string(rune('a' + i))); mark == 0 || !isNew {
			t.Fatalf("allocator returned mark=%d isNew=%v for a live allocation", mark, isNew)
		}
	}
}

func TestAllocatorExhaustion(t *testing.T) {
	a := NewAllocator(100, 2, nil)

	if mark, isNew := a.Allocate("user-a"); mark == 0 || !isNew {
		t.Fatalf("expected a new mark from a fresh pool, got mark=%d isNew=%v", mark, isNew)
	}
	if mark, isNew := a.Allocate("user-b"); mark == 0 || !isNew {
		t.Fatalf("expected a new mark from a fresh pool, got mark=%d isNew=%v", mark, isNew)
	}
	if mark, isNew := a.Allocate("user-c"); mark != 0 || isNew {
		t.Fatalf("expected 0/false once the pool is exhausted, got mark=%d isNew=%v", mark, isNew)
	}
	if mark, isNew := a.Allocate("user-d"); mark != 0 || isNew {
		t.Fatalf("expected 0/false on repeated exhausted allocation, got mark=%d isNew=%v", mark, isNew)
	}
}

func TestAllocatorConcurrent(t *testing.T) {
	a := NewAllocator(1, 500, nil)

	emails := make([]string, 500)
	for i := range emails {
		emails[i] = string(rune(i))
	}

	var wg sync.WaitGroup
	results := make([]uint32, len(emails))
	for i, email := range emails {
		wg.Add(1)
		go func(i int, email string) {
			defer wg.Done()
			results[i], _ = a.Allocate(email)
		}(i, email)
	}
	wg.Wait()

	seen := make(map[uint32]bool)
	for i, mark := range results {
		if mark == 0 {
			t.Fatalf("expected non-zero mark for email %d", i)
		}
		if seen[mark] {
			t.Fatalf("mark %d was allocated more than once", mark)
		}
		seen[mark] = true
	}

	for i, email := range emails {
		if again, isNew := a.Allocate(email); again != results[i] || isNew {
			t.Fatalf("expected stable mark %d with isNew=false for email %q, got %d isNew=%v", results[i], email, again, isNew)
		}
	}
}
