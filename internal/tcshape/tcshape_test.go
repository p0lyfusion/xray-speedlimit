package tcshape

import (
	"reflect"
	"testing"
)

func TestHtbBurstBytes(t *testing.T) {
	if got := htbBurstBytes(0, 0); got != 0 {
		t.Fatalf("burstMs=0 should disable burst, got %d", got)
	}
	// 10 Mbit/s = 1,250,000 bytes/sec; 100ms worth = 125,000 bytes.
	if got := htbBurstBytes(1_250_000, 100); got != 125_000 {
		t.Fatalf("got %d, want 125000", got)
	}
	// A tiny rate/duration should clamp to the floor, not round to ~0
	// (tc rejects a burst too small for the configured rate).
	if got := htbBurstBytes(10, 100); got != minHTBBurstBytes {
		t.Fatalf("got %d, want floor %d", got, minHTBBurstBytes)
	}
}

func TestHtbRateArgs(t *testing.T) {
	// 1,250,000 bytes/sec = 10,000,000 bit/s.
	got := htbRateArgs(1_250_000, 100)
	want := []string{"htb", "rate", "10000000bit", "burst", "125000b", "cburst", "125000b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	noBurst := htbRateArgs(1_250_000, 0)
	want = []string{"htb", "rate", "10000000bit"}
	if !reflect.DeepEqual(noBurst, want) {
		t.Fatalf("burstMs=0 should omit burst/cburst args, got %v", noBurst)
	}
}
