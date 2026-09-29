// Package mark computes a user's packet mark from their email.
//
// A mark is (queue+1)<<16 | minor. The upper half picks the TX queue, and
// so the per-queue HTB qdisc (whose handle is queue+1), and the lower half
// picks the user's class inside it. The mark is a pure function of the
// email and the queue count: it needs no state, can't run out, and is the
// same after a restart. Two emails can hash to the same mark and then
// share one class; with Q queues there are Q*65534 marks.
package mark

import "hash/fnv"

const (
	// MinMinor is the lowest class minor a mark uses. Minor 0 is not a
	// valid class and minor 1 is each HTB's default class.
	MinMinor = 2
	// MaxQueues is the most queues a mark can address: the queue field
	// is the 8 bits under QueueMask.
	MaxQueues = 255
	// QueueMask selects a mark's queue field (queue index + 1).
	QueueMask = 0xff0000

	minorsPerQueue = 0x10000 - MinMinor
)

// For returns email's mark for a device with the given number of TX
// queues (1..MaxQueues). The hash is FNV-1a and must never change: every
// user's mark, and so their class in the kernel, depends on it.
func For(email string, queues int) uint32 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(email))
	sum := h.Sum64()

	q := sum % uint64(queues)
	minor := MinMinor + (sum/uint64(queues))%minorsPerQueue
	return Join(uint32(q+1), uint32(minor))
}

// Join builds the mark for HTB major (queue index + 1) and class minor.
func Join(major, minor uint32) uint32 {
	return major<<16 | minor
}

// Split returns mark's HTB major (queue index + 1) and class minor. It
// reports ok=false for a value no mark from For with this many queues can
// take.
func Split(m uint32, queues int) (major, minor uint32, ok bool) {
	major, minor = m>>16, m&0xffff
	ok = major >= 1 && major <= uint32(queues) && minor >= MinMinor
	return major, minor, ok
}
