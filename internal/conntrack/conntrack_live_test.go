package conntrack_test

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
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

// requireConntrackMark lists the FAMILY_V4 conntrack table and asserts
// that the flow matching the given 4-tuple exists and carries want as its
// mark.
func requireConntrackMark(t *testing.T, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, want uint32) {
	t.Helper()

	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("listing conntrack table: %v", err)
	}
	for _, f := range flows {
		if f.Forward.SrcIP.Equal(srcIP) && f.Forward.SrcPort == srcPort &&
			f.Forward.DstIP.Equal(dstIP) && f.Forward.DstPort == dstPort {
			if f.Mark != want {
				t.Fatalf("conntrack mark = %d, want %d", f.Mark, want)
			}
			return
		}
	}
	t.Fatal("could not find conntrack entry for the test connection after marking")
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
// port, then connect to two different local IPs on the same port) to try
// to get one of their own connections riding unmarked; SetMark must mark
// every matching flow, not pick one or skip, so both of that user's
// connections stay correctly capped.
func TestLiveSetMarkMarksAllAmbiguousMatches(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: must run as root with CAP_NET_ADMIN")
	}
	activateConntrack(t)

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
	// is unknown.
	const sharedSrcPort = 48291
	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: sharedSrcPort}}
	client1, err := dialer.Dial("tcp4", ln1.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer client1.Close()
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
