package conntrack

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestProtocolNumber(t *testing.T) {
	if n, err := protocolNumber("tcp"); err != nil || n != unix.IPPROTO_TCP {
		t.Fatalf("protocolNumber(tcp) = %d, %v", n, err)
	}
	if _, err := protocolNumber("udp"); err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestIPFamilyOf(t *testing.T) {
	family, ip, err := ipFamilyOf(net.ParseIP("203.0.113.7"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if family != netlink.FAMILY_V4 || ip.String() != "203.0.113.7" {
		t.Fatalf("unexpected result: %v %v", family, ip)
	}

	family, ip, err = ipFamilyOf(net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if family != netlink.FAMILY_V6 || ip.String() != "2001:db8::1" {
		t.Fatalf("unexpected result: %v %v", family, ip)
	}

	if _, _, err := ipFamilyOf(nil); err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestFindFlowsExactMatch(t *testing.T) {
	flows := []*netlink.ConntrackFlow{
		{
			Forward: netlink.IPTuple{
				SrcIP: net.ParseIP("203.0.113.7"), SrcPort: 54203,
				DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
				Protocol: unix.IPPROTO_TCP,
			},
		},
		{
			Forward: netlink.IPTuple{
				SrcIP: net.ParseIP("203.0.113.8"), SrcPort: 1,
				DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
				Protocol: unix.IPPROTO_TCP,
			},
		},
	}

	matches := findFlows(flows, unix.IPPROTO_TCP, net.ParseIP("203.0.113.7"), 54203, net.ParseIP("198.51.100.1"), 443)
	if len(matches) != 1 || matches[0] != flows[0] {
		t.Fatalf("expected exactly the first flow to match, got %+v", matches)
	}

	if matches := findFlows(flows, unix.IPPROTO_TCP, net.ParseIP("203.0.113.9"), 1, net.ParseIP("198.51.100.1"), 443); len(matches) != 0 {
		t.Fatalf("expected no match, got %+v", matches)
	}
}

func TestFindFlowsNilDestinationMatchesWildcardCase(t *testing.T) {
	// Mirrors the real fallback: dstIP is nil (destination unknown/unusable),
	// so only the source 4-tuple plus destination port need to match.
	flows := []*netlink.ConntrackFlow{
		{
			Forward: netlink.IPTuple{
				SrcIP: net.ParseIP("5.44.39.162"), SrcPort: 51234,
				DstIP: net.ParseIP("5.129.238.61"), DstPort: 443,
				Protocol: unix.IPPROTO_TCP,
			},
		},
	}

	matches := findFlows(flows, unix.IPPROTO_TCP, net.ParseIP("5.44.39.162"), 51234, nil, 443)
	if len(matches) != 1 || matches[0] != flows[0] {
		t.Fatalf("expected the flow to match by source+dstPort alone, got %+v", matches)
	}
}

func TestFindFlowsRequiresDestinationIPWhenKnown(t *testing.T) {
	// Regression test for a multi-homed host: the same client source
	// 4-tuple can legally appear twice if it's connected to two different
	// local IPs on this box (the OS only needs the destination IP to
	// differ for both tuples to be valid simultaneously). When a real
	// destination IP is available, it must still be used to pick the
	// right one -- dropping it unconditionally would let a webhook for
	// one connection mark the other by mistake.
	wantFlow := &netlink.ConntrackFlow{
		Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("203.0.113.7"), SrcPort: 54203,
			DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			Protocol: unix.IPPROTO_TCP,
		},
	}
	otherFlow := &netlink.ConntrackFlow{
		Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("203.0.113.7"), SrcPort: 54203,
			DstIP: net.ParseIP("198.51.100.2"), DstPort: 443,
			Protocol: unix.IPPROTO_TCP,
		},
	}
	flows := []*netlink.ConntrackFlow{otherFlow, wantFlow}

	matches := findFlows(flows, unix.IPPROTO_TCP, net.ParseIP("203.0.113.7"), 54203, net.ParseIP("198.51.100.1"), 443)
	if len(matches) != 1 || matches[0] != wantFlow {
		t.Fatalf("expected to pick only the flow matching the real destination IP, got %+v", matches)
	}
}

func TestFindFlowsReturnsAllMatchesWithUnknownDestination(t *testing.T) {
	// Same multi-homed collision as above, but this time the destination
	// IP is unknown (nil). Both flows must be returned: SetMark marks all
	// of them rather than guessing, since on a multi-homed host a user can
	// trivially self-trigger this ambiguity (bind an explicit local port,
	// open two connections to two different local IPs on the same port)
	// and both connections genuinely belong to that same user/mark --
	// marking only one would leave the other free to bypass its cap.
	flowA := &netlink.ConntrackFlow{
		Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("203.0.113.7"), SrcPort: 54203,
			DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			Protocol: unix.IPPROTO_TCP,
		},
	}
	flowB := &netlink.ConntrackFlow{
		Forward: netlink.IPTuple{
			SrcIP: net.ParseIP("203.0.113.7"), SrcPort: 54203,
			DstIP: net.ParseIP("198.51.100.2"), DstPort: 443,
			Protocol: unix.IPPROTO_TCP,
		},
	}
	flows := []*netlink.ConntrackFlow{flowA, flowB}

	matches := findFlows(flows, unix.IPPROTO_TCP, net.ParseIP("203.0.113.7"), 54203, nil, 443)
	if len(matches) != 2 || matches[0] != flowA || matches[1] != flowB {
		t.Fatalf("expected both flows returned, got %+v", matches)
	}
}
