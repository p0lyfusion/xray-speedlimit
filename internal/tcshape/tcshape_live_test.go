package tcshape_test

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/p0lyfusion/xray-speedlimit/internal/tcshape"
)

const (
	liveIface  = "xsl-test0"
	livePeer   = "xsl-test1"
	liveQueues = 4
)

// setupLiveVeth creates a veth pair with 8 TX queues (liveQueues of them
// shaped) and routes
// a peer address of each family out of it through a static neighbour
// entry, so packets sent to those addresses really leave liveIface and go
// through its qdisc. (An address assigned locally would be delivered over
// loopback instead.) It skips unless run as root with tc, ip and nft;
// "unshare -rn" is the easy way to get that without touching the host.
func setupLiveVeth(t *testing.T) (peer4, peer6 net.IP) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN (e.g. under unshare -rn)")
	}
	for _, tool := range []string{"tc", "ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not installed", tool)
		}
	}

	ip := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Skipf("skipping: ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	// More queues allocated than the shaper uses, like a NIC whose
	// queue count was lowered with ethtool -L: the mq has classes with no
	// HTB under them.
	ip("link", "add", liveIface, "numtxqueues", "8", "type", "veth", "peer", "name", livePeer, "numtxqueues", "8")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", liveIface).Run() })
	ip("addr", "add", "10.99.0.1/24", "dev", liveIface)
	ip("addr", "add", "fd99::1/64", "dev", liveIface, "nodad")
	ip("link", "set", liveIface, "up")
	ip("link", "set", livePeer, "up")
	peerMAC := strings.Fields(ip("-br", "link", "show", livePeer))[2]
	ip("neigh", "add", "10.99.0.2", "lladdr", peerMAC, "dev", liveIface)
	ip("-6", "neigh", "add", "fd99::2", "lladdr", peerMAC, "dev", liveIface)
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", "xray_speedlimit").Run() })
	return net.ParseIP("10.99.0.2"), net.ParseIP("fd99::2")
}

// sendMarked sends n UDP packets carrying mark to dst.
func sendMarked(t *testing.T, dst net.IP, mark uint32, n int) {
	t.Helper()
	d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return sockErr
	}}
	conn, err := d.Dial("udp", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		t.Fatalf("dial %s: %v", dst, err)
	}
	defer conn.Close()
	for range n {
		if _, err := conn.Write(make([]byte, 500)); err != nil {
			t.Fatalf("send to %s: %v", dst, err)
		}
	}
}

func classBytes(t *testing.T, s *tcshape.Shaper) map[uint32]uint64 {
	t.Helper()
	classes, err := s.Classes()
	if err != nil {
		t.Fatalf("Classes: %v", err)
	}
	got := make(map[uint32]uint64)
	for _, c := range classes {
		got[c.Mark] = c.Bytes
	}
	return got
}

// TestLiveLayoutShapesMarkedTraffic builds the layout on a 4-queue veth
// and checks that marked IPv4 and IPv6 packets end up in their mark's
// class, which only happens if the steering filter put them on the right
// TX queue and that queue's fw classifier mapped the mark to the class.
func TestLiveLayoutShapesMarkedTraffic(t *testing.T) {
	peer4, peer6 := setupLiveVeth(t)

	s := tcshape.New(liveIface, liveQueues, 100)
	if exists, err := s.LayoutExists(); err != nil || exists {
		t.Fatalf("LayoutExists on a fresh veth = %v, %v; want false", exists, err)
	}
	if err := s.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if exists, err := s.LayoutExists(); err != nil || !exists {
		t.Fatalf("LayoutExists after EnsureRoot = %v, %v; want true", exists, err)
	}

	// One mark per queue: without steering, each socket's packets would
	// sit on whichever queue the kernel picked, so all four landing in
	// their class by chance is a 1 in 256 event.
	marks4 := []uint32{0x1002a, 0x2002a, 0x3002a, 0x4002a}
	const mark6 = 0x1ffff
	for _, m := range append(marks4, mark6) {
		if err := s.SetRate(m, 1_000_000); err != nil {
			t.Fatalf("SetRate(%#x): %v", m, err)
		}
	}
	for _, m := range marks4 {
		sendMarked(t, peer4, m, 10)
	}
	sendMarked(t, peer6, mark6, 10)

	got := classBytes(t, s)
	for _, m := range append(marks4, mark6) {
		if got[m] < 10*500 {
			t.Fatalf("class bytes = %v; want at least 5000 in %#x", got, m)
		}
	}
}

// TestLiveEnsureRootAdoptsAndRepairs checks that a restart keeps an
// existing layout and its classes, and that it rebuilds steering filters
// someone removed.
func TestLiveEnsureRootAdoptsAndRepairs(t *testing.T) {
	peer4, _ := setupLiveVeth(t)

	s := tcshape.New(liveIface, liveQueues, 100)
	if err := s.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	const m = 0x2002a
	if err := s.SetRate(m, 1_000_000); err != nil {
		t.Fatalf("SetRate: %v", err)
	}

	if out, err := exec.Command("tc", "filter", "del", "dev", liveIface, "egress", "pref", "49000").CombinedOutput(); err != nil {
		t.Fatalf("removing steering filters: %v: %s", err, out)
	}

	restarted := tcshape.New(liveIface, liveQueues, 100)
	exists, err := restarted.LayoutExists()
	if err != nil || !exists {
		t.Fatalf("LayoutExists = %v, %v; want true", exists, err)
	}
	if err := restarted.EnsureRoot(exists, 1000); err != nil {
		t.Fatalf("EnsureRoot on restart: %v", err)
	}

	sendMarked(t, peer4, m, 10)
	if got := classBytes(t, restarted); got[m] < 10*500 {
		t.Fatalf("class bytes after restart = %v; want the adopted class %#x to carry traffic", got, m)
	}
}

// TestLiveEnsureRootReplacesOldLayout checks the migration from the
// single root HTB older versions built.
func TestLiveEnsureRootReplacesOldLayout(t *testing.T) {
	peer4, _ := setupLiveVeth(t)
	for _, args := range [][]string{
		{"qdisc", "add", "dev", liveIface, "root", "handle", "1:", "htb", "default", "1"},
		{"class", "add", "dev", liveIface, "parent", "1:", "classid", "1:1", "htb", "rate", "1gbit"},
		{"class", "add", "dev", liveIface, "parent", "1:", "classid", "1:2710", "htb", "rate", "1mbit"},
	} {
		if out, err := exec.Command("tc", args...).CombinedOutput(); err != nil {
			t.Fatalf("tc %v: %v: %s", args, err, out)
		}
	}

	s := tcshape.New(liveIface, liveQueues, 100)
	if exists, err := s.LayoutExists(); err != nil || exists {
		t.Fatalf("LayoutExists with the old layout = %v, %v; want false", exists, err)
	}
	if err := s.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}
	if got := classBytes(t, s); len(got) != 0 {
		t.Fatalf("classes after migration = %v; want none (the old tree is dropped)", got)
	}

	const m = 0x4002a
	if err := s.SetRate(m, 1_000_000); err != nil {
		t.Fatalf("SetRate: %v", err)
	}
	sendMarked(t, peer4, m, 10)
	if got := classBytes(t, s); got[m] < 10*500 {
		t.Fatalf("class bytes = %v; want traffic in %#x", got, m)
	}
}

// TestLiveEnsureRootRebuildsOverOwnLayout checks the rebuilds that start
// from this package's own mq root: a queue count change, and a tree left
// half-built by an earlier start.
func TestLiveEnsureRootRebuildsOverOwnLayout(t *testing.T) {
	peer4, _ := setupLiveVeth(t)

	s := tcshape.New(liveIface, liveQueues, 100)
	if err := s.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot: %v", err)
	}

	fewer := tcshape.New(liveIface, 2, 100)
	if exists, err := fewer.LayoutExists(); err != nil || exists {
		t.Fatalf("LayoutExists for 2 queues over a 4-queue layout = %v, %v; want false", exists, err)
	}
	if err := fewer.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot rebuilding for 2 queues: %v", err)
	}
	if exists, err := fewer.LayoutExists(); err != nil || !exists {
		t.Fatalf("LayoutExists after rebuilding for 2 queues = %v, %v; want true", exists, err)
	}

	// A start that died partway through the build leaves a queue without
	// its HTB.
	if out, err := exec.Command("tc", "qdisc", "del", "dev", liveIface, "parent", "8000:2").CombinedOutput(); err != nil {
		t.Fatalf("removing one queue's HTB: %v: %s", err, out)
	}
	if exists, err := fewer.LayoutExists(); err != nil || exists {
		t.Fatalf("LayoutExists with a queue's HTB missing = %v, %v; want false", exists, err)
	}
	if err := fewer.EnsureRoot(false, 1000); err != nil {
		t.Fatalf("EnsureRoot rebuilding a half-built layout: %v", err)
	}

	const m = 0x2002a
	if err := fewer.SetRate(m, 1_000_000); err != nil {
		t.Fatalf("SetRate: %v", err)
	}
	sendMarked(t, peer4, m, 10)
	if got := classBytes(t, fewer); got[m] < 10*500 {
		t.Fatalf("class bytes = %v; want traffic in %#x", got, m)
	}
}

// TestLiveEnsureRootAcceptsFallbackDefaultRate builds the layout at the
// rate main falls back to when the interface reports no link speed
// (fallbackDefaultClassRateMbit). It is 10x the rate the other live
// tests use, and -htb-burst-ms turns it into a 125 MB burst, so it is
// worth checking that tc takes it and that traffic still reaches a
// per-user class under so large a default class.
func TestLiveEnsureRootAcceptsFallbackDefaultRate(t *testing.T) {
	peer4, _ := setupLiveVeth(t)

	s := tcshape.New(liveIface, liveQueues, 100)
	if err := s.EnsureRoot(false, 10_000); err != nil {
		t.Fatalf("EnsureRoot at the fallback default rate: %v", err)
	}

	const m = 0x3002a
	if err := s.SetRate(m, 1_000_000); err != nil {
		t.Fatalf("SetRate: %v", err)
	}
	sendMarked(t, peer4, m, 10)
	if got := classBytes(t, s); got[m] < 10*500 {
		t.Fatalf("class bytes = %v; want traffic in %#x", got, m)
	}
}
