package webhook

import (
	"testing"
	"time"

	"github.com/p0lyfusion/xray-speedlimit/internal/mark"
)

func TestUsersMark(t *testing.T) {
	u := NewUsers(48)
	m := u.Mark("user-a")
	if m != mark.For("user-a", 48) || u.Mark("user-a") != m {
		t.Fatalf("Mark(user-a) = %#x, want the stable %#x", m, mark.For("user-a", 48))
	}
	if u.Mark("") != 0 {
		t.Fatal("empty email must get no mark")
	}
	if got := u.Marks(); len(got) != 1 || got["user-a"] != m {
		t.Fatalf("Marks() = %v", got)
	}
}

func TestUsersPrune(t *testing.T) {
	u := NewUsers(4)
	now := time.Unix(1_000_000, 0)
	u.now = func() time.Time { return now }

	u.Mark("old")
	now = now.Add(2 * time.Hour)
	u.Mark("recent")
	u.Prune(time.Hour)

	got := u.Marks()
	if _, ok := got["old"]; ok || len(got) != 1 {
		t.Fatalf("after Prune: %v, want only recent", got)
	}
}
