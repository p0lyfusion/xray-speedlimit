// Package limiter defines the mark -> rate store abstraction used by the
// HTTP API, decoupled from tc/HTB so the API can be unit tested without a
// kernel.
package limiter

// Entry is one mark -> rate mapping.
type Entry struct {
	Mark            uint32 `json:"mark"`
	RateBytesPerSec uint32 `json:"rate_bytes_per_sec"`
}

// Store manages the mark -> rate mappings.
type Store interface {
	Set(mark uint32, rateBytesPerSec uint32) error
	Delete(mark uint32) error
	List() ([]Entry, error)
}
