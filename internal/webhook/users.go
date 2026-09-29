package webhook

import (
	"maps"
	"sync"
	"time"

	"github.com/p0lyfusion/xray-speedlimit/internal/mark"
)

type userEntry struct {
	mark     uint32
	lastSeen time.Time
}

// Users gives each email its mark (see internal/mark) and remembers the
// emails seen recently, for GET /users.
type Users struct {
	queues int
	now    func() time.Time

	mu    sync.Mutex
	users map[string]userEntry
}

// NewUsers creates a Users for a device with queues TX queues.
func NewUsers(queues int) *Users {
	return &Users{queues: queues, now: time.Now, users: make(map[string]userEntry)}
}

// Mark returns email's mark and records that email was seen. It returns 0
// for an empty email; callers must treat 0 as "do not set a mark".
func (u *Users) Mark(email string) uint32 {
	if email == "" {
		return 0
	}
	now := u.now()
	u.mu.Lock()
	defer u.mu.Unlock()
	e, ok := u.users[email]
	if !ok {
		e.mark = mark.For(email, u.queues)
	}
	e.lastSeen = now
	u.users[email] = e
	return e.mark
}

// Marks returns a copy of the email -> mark table.
func (u *Users) Marks() map[string]uint32 {
	u.mu.Lock()
	defer u.mu.Unlock()
	marks := make(map[string]uint32, len(u.users))
	for email, e := range u.users {
		marks[email] = e.mark
	}
	return marks
}

// Prune forgets emails not seen for idle, so the table only holds recent
// users.
func (u *Users) Prune(idle time.Duration) {
	cutoff := u.now().Add(-idle)
	u.mu.Lock()
	defer u.mu.Unlock()
	maps.DeleteFunc(u.users, func(_ string, e userEntry) bool { return e.lastSeen.Before(cutoff) })
}
