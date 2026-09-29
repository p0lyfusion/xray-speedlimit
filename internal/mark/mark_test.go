package mark

import (
	"fmt"
	"testing"
)

// TestForIsStable pins For's output. If this fails, every deployed user's
// mark would change on upgrade: don't update the vectors, fix the hash.
func TestForIsStable(t *testing.T) {
	cases := []struct {
		email  string
		queues int
		want   uint32
	}{
		{"alice@example.com", 48, 0x171909},
		{"a", 48, 0x1dff6f},
		{"a", 1, 0x1e4ec},
		{"", 48, 0x63ffa},
	}
	for _, tc := range cases {
		if got := For(tc.email, tc.queues); got != tc.want {
			t.Errorf("For(%q, %d) = %#x, want %#x", tc.email, tc.queues, got, tc.want)
		}
	}
}

func TestForStaysInRange(t *testing.T) {
	for _, queues := range []int{1, 4, 48, MaxQueues} {
		for i := range 20000 {
			m := For(fmt.Sprintf("user-%d", i), queues)
			if _, _, ok := Split(m, queues); !ok {
				t.Fatalf("For(user-%d, %d) = %#x is outside the valid range", i, queues, m)
			}
		}
	}
}

func TestForSpreadsAcrossQueues(t *testing.T) {
	const queues, users = 48, 48000
	perQueue := make([]int, queues+1)
	for i := range users {
		major, _, _ := Split(For(fmt.Sprintf("user-%d", i), queues), queues)
		perQueue[major]++
	}
	for q := 1; q <= queues; q++ {
		if n := perQueue[q]; n < users/queues*8/10 || n > users/queues*12/10 {
			t.Fatalf("queue %d got %d of %d users, want about %d", q, n, users, users/queues)
		}
	}
}

func TestSplit(t *testing.T) {
	cases := []struct {
		mark         uint32
		major, minor uint32
		ok           bool
	}{
		{0x3002a, 3, 0x2a, true},
		{0x30002, 3, 2, true},
		{0x3ffff, 3, 0xffff, true},
		{0x30001, 3, 1, false}, // default class
		{0x30000, 3, 0, false},
		{0x2a, 0, 0x2a, false}, // no queue: an old-style 16-bit mark
		{0x5002a, 5, 0x2a, false},
	}
	for _, tc := range cases {
		major, minor, ok := Split(tc.mark, 4)
		if major != tc.major || minor != tc.minor || ok != tc.ok {
			t.Errorf("Split(%#x, 4) = %d, %#x, %v; want %d, %#x, %v", tc.mark, major, minor, ok, tc.major, tc.minor, tc.ok)
		}
	}
}
