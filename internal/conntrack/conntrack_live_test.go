package conntrack_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/p0lyfusion/xray-speedlimit/internal/conntrack"
)

// activateConntrack loads a throwaway nftables rule that references ct
// state. Netfilter only starts tracking connections in a network
// namespace once something actually asks for conntrack info; a pristine
// namespace (as most CI runners are, unlike a Docker-managed bridge
// namespace, which already has Docker's own NAT rules doing this) never
// creates entries at all, which looks identical to "mark not found" from
// the caller's side. Production never hits this because tcshape.EnsureRoot
// loads exactly this kind of rule before the webhook handler goes live;
// this test has to do the same to be representative.
func activateConntrack(t *testing.T) {
	t.Helper()
	table := "conntrack_live_test"
	if out, err := exec.Command("nft", "add", "table", "inet", table).CombinedOutput(); err != nil {
		t.Skipf("skipping: cannot activate conntrack via nft (need nftables): %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "inet", table).Run() })
	if out, err := exec.Command("nft", "add", "chain", "inet", table, "output",
		"{", "type", "filter", "hook", "output", "priority", "0", ";", "}").CombinedOutput(); err != nil {
		t.Skipf("skipping: cannot add nft chain: %v: %s", err, out)
	}
	if out, err := exec.Command("nft", "add", "rule", "inet", table, "output", "ct", "state", "new", "counter").CombinedOutput(); err != nil {
		t.Skipf("skipping: cannot add nft rule: %v: %s", err, out)
	}
}

// dialLoopback opens a real loopback TCP connection (listen on
// 127.0.0.1:0, accept in the background, dial), returning the accepted
// client conn and its local/remote addresses. Both ends are closed via
// t.Cleanup.
func dialLoopback(t *testing.T) (client net.Conn, srcAddr, dstAddr *net.TCPAddr) {
	t.Helper()

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	client, err = net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	select {
	case conn := <-accepted:
		t.Cleanup(func() { conn.Close() })
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept")
	}

	return client, client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
}

// assignLoopbackAddr adds ip/32 to lo for the duration of the test,
// unless it is already assigned (in which case it is left as it is).
func assignLoopbackAddr(t *testing.T, ip string) {
	t.Helper()
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", "lo").CombinedOutput()
	if err != nil {
		t.Skipf("skipping: cannot list lo addresses: %v: %s", err, out)
	}
	if strings.Contains(string(out), " "+ip+"/") {
		return
	}
	if out, err := exec.Command("ip", "addr", "add", ip+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Skipf("skipping: cannot add %s to lo: %v: %s", ip, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "addr", "del", ip+"/32", "dev", "lo").Run() })
}

// findFlow returns the conntrack flow with the given original tuple, or
// nil.
func findFlow(t *testing.T, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) *netlink.ConntrackFlow {
	t.Helper()
	family := netlink.InetFamily(netlink.FAMILY_V4)
	if srcIP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		t.Fatalf("listing conntrack table: %v", err)
	}
	for _, f := range flows {
		if f.Forward.SrcIP.Equal(srcIP) && f.Forward.SrcPort == srcPort &&
			f.Forward.DstIP.Equal(dstIP) && f.Forward.DstPort == dstPort {
			return f
		}
	}
	return nil
}

// skipIfPermissionDenied skips the test if err indicates the process
// lacks CAP_NET_ADMIN, otherwise fails it with msg as context.
func skipIfPermissionDenied(t *testing.T, err error, msg string) {
	t.Helper()
	if err == nil {
		return
	}
	if errors.Is(err, unix.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
		t.Skipf("skipping: insufficient privileges to use netlink conntrack (need CAP_NET_ADMIN): %v", err)
	}
	t.Fatalf("%s: %v", msg, err)
}

// requireConntrackMark lists the conntrack table and asserts
// that the flow matching the given 4-tuple exists and carries want as its
// mark.
func requireConntrackMark(t *testing.T, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, want uint32) {
	t.Helper()

	f := findFlow(t, srcIP, srcPort, dstIP, dstPort)
	if f == nil {
		t.Fatal("could not find conntrack entry for the test connection after marking")
	}
	if f.Mark != want {
		t.Fatalf("conntrack mark = %d, want %d", f.Mark, want)
	}
}

// TestLiveSetMark opens a real loopback TCP connection, marks it through
// the kernel conntrack table and reads the mark back via
// netlink.ConntrackTableList to confirm it landed. It needs root with
// CAP_NET_ADMIN and the nf_conntrack_netlink module; anywhere else it
// skips with the reason.
func TestLiveSetMark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	_, srcAddr, dstAddr := dialLoopback(t)

	const mark = uint32(4242)
	m := conntrack.NewMarker(nil)
	err := m.SetMark("tcp", srcAddr.IP, uint16(srcAddr.Port), dstAddr.IP, uint16(dstAddr.Port), mark)
	skipIfPermissionDenied(t, err, "SetMark")

	requireConntrackMark(t, srcAddr.IP, uint16(srcAddr.Port), dstAddr.IP, uint16(dstAddr.Port), mark)
}

// TestLiveSetMarkIgnoresBrokenDestinationIP reproduces a real failure
// observed in production: Xray-core's webhook reported a client's
// destination/local address as "::" (IPv6 unspecified) for an IPv4
// client's connection -- a documented limitation of at least its UDP
// worker (app/proxyman/inbound/worker.go), and observed on a TCP-based
// transport too. SetMark must still find and mark the real conntrack
// entry using the source 4-tuple plus destination port alone, ignoring
// whatever destination IP it was handed.
func TestLiveSetMarkIgnoresBrokenDestinationIP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	_, srcAddr, dstAddr := dialLoopback(t)

	const mark = uint32(4343)
	m := conntrack.NewMarker(nil)
	brokenDstIP := net.ParseIP("::") // exactly what was observed from Xray
	err := m.SetMark("tcp", srcAddr.IP, uint16(srcAddr.Port), brokenDstIP, uint16(dstAddr.Port), mark)
	skipIfPermissionDenied(t, err, "SetMark with broken destination IP")

	requireConntrackMark(t, srcAddr.IP, uint16(srcAddr.Port), dstAddr.IP, uint16(dstAddr.Port), mark)
}

// TestLiveSetMarkMarksAllAmbiguousMatches reproduces a genuine
// multi-homed collision -- the same client source IP:port holds two
// simultaneous connections to the same destination port on two different
// local IPs (127.0.0.1 and 127.0.0.2, both real loopback addresses), and
// the destination IP Xray reported is the broken wildcard sentinel, so
// both flows match on source 4-tuple plus destination port alone. This is
// exactly what a user can self-trigger on demand (bind an explicit local
// port with SO_REUSEADDR, then connect to two different local IPs on the
// same port) to try
// to get one of their own connections riding unmarked; SetMark must mark
// every matching flow, not pick one or skip, so both of that user's
// connections stay correctly capped.
func TestLiveSetMarkMarksAllAmbiguousMatches(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)
	// A wildcard lookup only tries addresses assigned to an interface,
	// and lo normally only has 127.0.0.1/8.
	assignLoopbackAddr(t, "127.0.0.2")

	ln1, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	defer ln1.Close()
	sharedPort := ln1.Addr().(*net.TCPAddr).Port

	ln2, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.2:%d", sharedPort))
	if err != nil {
		t.Fatalf("listen on 127.0.0.2:%d: %v", sharedPort, err)
	}
	defer ln2.Close()

	accepted1 := make(chan net.Conn, 1)
	go func() {
		conn, err := ln1.Accept()
		if err == nil {
			accepted1 <- conn
		}
	}()
	accepted2 := make(chan net.Conn, 1)
	go func() {
		conn, err := ln2.Accept()
		if err == nil {
			accepted2 <- conn
		}
	}()

	// Same source IP:port dialing two different destination IPs on the
	// same port is a legal, non-colliding pair of 4-tuples for the OS,
	// which is exactly what makes this ambiguous once the destination IP
	// is unknown. Binding the second socket to a port the first one
	// already holds needs SO_REUSEADDR on both; without it the second
	// dial fails with EADDRINUSE. The first dial picks a free port, so
	// the test can't collide with anything else on the host.
	reuseAddr := func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return sockErr
	}
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}, Control: reuseAddr}
	client1, err := dialer.Dial("tcp4", ln1.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer client1.Close()
	sharedSrcPort := uint16(client1.LocalAddr().(*net.TCPAddr).Port)
	dialer.LocalAddr = client1.LocalAddr()
	client2, err := dialer.Dial("tcp4", ln2.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer client2.Close()

	for _, ch := range []chan net.Conn{accepted1, accepted2} {
		select {
		case conn := <-ch:
			defer conn.Close()
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for accept")
		}
	}

	m := conntrack.NewMarker(nil)
	const mark = uint32(4444)
	brokenDstIP := net.ParseIP("0.0.0.0") // exactly what was observed from Xray for a v4 client
	err = m.SetMark("tcp", net.ParseIP("127.0.0.1"), sharedSrcPort, brokenDstIP, uint16(sharedPort), mark)
	skipIfPermissionDenied(t, err, "SetMark with ambiguous match")

	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("listing conntrack table: %v", err)
	}
	marked := 0
	for _, f := range flows {
		if f.Forward.SrcIP.Equal(net.ParseIP("127.0.0.1")) && f.Forward.SrcPort == sharedSrcPort && f.Forward.DstPort == uint16(sharedPort) {
			if f.Mark != mark {
				t.Fatalf("ambiguous flow (dst %s) was not marked; SetMark should mark every matching flow", f.Forward.DstIP)
			}
			marked++
		}
	}
	if marked != 2 {
		t.Fatalf("expected both ambiguous flows marked, found %d", marked)
	}
}

// TestLiveSetMarkKeepsTimeout checks that marking only changes the mark:
// an update that also sent CTA_TIMEOUT could leave an established flow
// about to expire, taking its mark with it.
func TestLiveSetMarkKeepsTimeout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	_, srcAddr, dstAddr := dialLoopback(t)
	srcPort, dstPort := uint16(srcAddr.Port), uint16(dstAddr.Port)

	m := conntrack.NewMarker(nil)
	err := m.SetMark("tcp", srcAddr.IP, srcPort, dstAddr.IP, dstPort, 4545)
	skipIfPermissionDenied(t, err, "SetMark")

	f := findFlow(t, srcAddr.IP, srcPort, dstAddr.IP, dstPort)
	if f == nil {
		t.Fatal("could not find conntrack entry for the test connection after marking")
	}
	// Established TCP flows default to a 5-day timeout; anything near
	// zero means the update clobbered it.
	if f.TimeOut < 3600 {
		t.Fatalf("conntrack timeout after marking = %ds, want the established timeout left alone", f.TimeOut)
	}
}

// TestLiveSetMarkMissCreatesNothing checks that marking a tuple with no
// conntrack entry fails and doesn't insert one.
func TestLiveSetMarkMissCreatesNothing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	_, srcAddr, dstAddr := dialLoopback(t)
	// A source port nothing is using: the tuple can't exist.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	unusedPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()

	m := conntrack.NewMarker(nil)
	for _, dst := range []net.IP{dstAddr.IP, net.ParseIP("::")} {
		err := m.SetMark("tcp", srcAddr.IP, unusedPort, dst, uint16(dstAddr.Port), 4646)
		if errors.Is(err, unix.EPERM) {
			skipIfPermissionDenied(t, err, "SetMark")
		}
		if err == nil || !strings.Contains(err.Error(), "no conntrack entry") {
			t.Fatalf("SetMark with dst %s on a missing tuple: got %v, want a no conntrack entry error", dst, err)
		}
	}
	if f := findFlow(t, srcAddr.IP, unusedPort, dstAddr.IP, uint16(dstAddr.Port)); f != nil {
		t.Fatalf("SetMark on a missing tuple created a conntrack entry: %v", f)
	}
}

// TestLiveSetMarkIPv6 marks an IPv6 loopback connection, first by its
// exact tuple and then through the "::" wildcard.
func TestLiveSetMarkIPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("skipping: no IPv6 loopback: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	client, err := net.Dial("tcp6", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept")
	}
	srcAddr, dstAddr := client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)
	srcPort, dstPort := uint16(srcAddr.Port), uint16(dstAddr.Port)

	m := conntrack.NewMarker(nil)
	err = m.SetMark("tcp", srcAddr.IP, srcPort, dstAddr.IP, dstPort, 4747)
	skipIfPermissionDenied(t, err, "SetMark over IPv6")
	requireConntrackMark(t, srcAddr.IP, srcPort, dstAddr.IP, dstPort, 4747)

	if err := m.SetMark("tcp", srcAddr.IP, srcPort, net.ParseIP("::"), dstPort, 4748); err != nil {
		t.Fatalf("SetMark over IPv6 with wildcard destination: %v", err)
	}
	requireConntrackMark(t, srcAddr.IP, srcPort, dstAddr.IP, dstPort, 4748)
}

// TestLiveDiagnose checks what Diagnose reports for a live, tracked
// connection, and for a client port with no connection behind it.
func TestLiveDiagnose(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

	_, srcAddr, dstAddr := dialLoopback(t)
	m := conntrack.NewMarker(nil)

	d, err := m.Diagnose(srcAddr.IP, uint16(srcAddr.Port), uint16(dstAddr.Port))
	skipIfPermissionDenied(t, err, "Diagnose")
	if len(d.ClientSockets) != 1 || !d.Listening || len(d.ClientFlows) == 0 || d.ConntrackTotal == 0 || d.PeersOnPortCount != 1 {
		t.Fatalf("unexpected diagnosis of a live connection: %+v", d)
	}

	d, err = m.Diagnose(srcAddr.IP, 1, uint16(dstAddr.Port))
	if err != nil {
		t.Fatalf("Diagnose: %v", err)
	}
	if len(d.ClientSockets) != 0 || !strings.Contains(d.Hint, "no TCP socket from this client IP:port, but conntrack") {
		t.Fatalf("unexpected diagnosis of a port with no connection: %+v", d)
	}
}
