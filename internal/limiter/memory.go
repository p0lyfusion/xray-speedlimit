package limiter

import "sync"

// memoryStore is a Store backed by a plain map. It is the base that
// tcshape.WrapStore layers tc/HTB enforcement on top of.
type memoryStore struct {
	mu      sync.Mutex
	entries map[uint32]uint32
}

// NewMemoryStore creates an empty in-memory Store.
func NewMemoryStore() Store {
	return &memoryStore{entries: make(map[uint32]uint32)}
}

func (s *memoryStore) Set(mark uint32, rateBytesPerSec uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[mark] = rateBytesPerSec
	return nil
}

func (s *memoryStore) Delete(mark uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, mark)
	return nil
}

func (s *memoryStore) List() ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]Entry, 0, len(s.entries))
	for mark, rate := range s.entries {
		entries = append(entries, Entry{Mark: mark, RateBytesPerSec: rate})
	}
	return entries, nil
}
