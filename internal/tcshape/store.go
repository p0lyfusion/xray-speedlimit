package tcshape

import (
	"log/slog"
	"sync"

	"github.com/p0lyfusion/xray-speedlimit/internal/limiter"
)

// RateShaper is the subset of *Shaper that WrapStore needs, so tests can
// substitute a fake.
type RateShaper interface {
	SetRate(mark uint32, rateBytesPerSec uint32) error
	Remove(mark uint32) error
}

type shapedStore struct {
	// mu makes each Set/Delete's tc change and base update one step.
	// Without it, a concurrent Set and Delete of the same mark can
	// interleave (Set's tc, Delete's tc, Delete's base, Set's base) and
	// leave List showing a limit whose class no longer exists.
	mu     sync.Mutex
	base   limiter.Store
	shaper RateShaper
	log    *slog.Logger
}

// WrapStore wraps base so that every Set/Delete also creates/updates or
// removes the matching tc/HTB class, keeping the mark->rate store and
// the enforcement layer in sync.
func WrapStore(base limiter.Store, shaper RateShaper, log *slog.Logger) limiter.Store {
	if log == nil {
		log = slog.Default()
	}
	return &shapedStore{base: base, shaper: shaper, log: log}
}

// Set applies the rate in tc first and only records it in base once that
// succeeds, so a tc failure (e.g. a mark outside the 16-bit classid range)
// never shows up in List as a limit that isn't actually enforced.
func (s *shapedStore) Set(mark uint32, rate uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.shaper.SetRate(mark, rate); err != nil {
		s.log.Error("tc shaping: failed to apply rate", "mark", mark, "error", err)
		return err
	}
	return s.base.Set(mark, rate)
}

// Delete removes the tc class first, for the same reason as Set: if that
// fails, the mark is still limited and must stay in List.
func (s *shapedStore) Delete(mark uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.shaper.Remove(mark); err != nil {
		s.log.Error("tc shaping: failed to remove class", "mark", mark, "error", err)
		return err
	}
	return s.base.Delete(mark)
}

func (s *shapedStore) List() ([]limiter.Entry, error) {
	return s.base.List()
}
