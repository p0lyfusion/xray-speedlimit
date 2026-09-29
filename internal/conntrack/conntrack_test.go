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

func TestCandidateDstsSpecified(t *testing.T) {
	local := []net.IP{net.ParseIP("198.51.100.1"), net.ParseIP("198.51.100.2")}

	got := candidateDsts(net.ParseIP("198.51.100.1"), netlink.FAMILY_V4, local)
	if len(got) != 1 || !got[0].Equal(net.ParseIP("198.51.100.1")) || len(got[0]) != net.IPv4len {
		t.Fatalf("expected only the given 4-byte destination, got %v", got)
	}

	// A known destination is used as is even if it isn't a local address.
	got = candidateDsts(net.ParseIP("203.0.113.9"), netlink.FAMILY_V4, local)
	if len(got) != 1 || !got[0].Equal(net.ParseIP("203.0.113.9")) {
		t.Fatalf("expected the given destination, got %v", got)
	}

	if got := candidateDsts(net.ParseIP("2001:db8::1"), netlink.FAMILY_V4, local); len(got) != 0 {
		t.Fatalf("expected no candidates for a destination of the wrong family, got %v", got)
	}
}

func TestCandidateDstsWildcardUsesSourceFamily(t *testing.T) {
	local := []net.IP{
		net.ParseIP("127.0.0.1"),
		net.ParseIP("::1"),
		net.ParseIP("198.51.100.1"),
		net.ParseIP("2001:db8::1"),
		net.ParseIP("198.51.100.2"),
	}

	// Xray reports "::" for IPv4 clients too; the family comes from the
	// source, not from the wildcard.
	for _, wildcard := range []string{"::", "0.0.0.0"} {
		got := candidateDsts(net.ParseIP(wildcard), netlink.FAMILY_V4, local)
		want := []string{"127.0.0.1", "198.51.100.1", "198.51.100.2"}
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", wildcard, got, want)
		}
		for i := range want {
			if got[i].String() != want[i] || len(got[i]) != net.IPv4len {
				t.Fatalf("%s: got %v, want %v", wildcard, got, want)
			}
		}
	}

	got := candidateDsts(net.ParseIP("::"), netlink.FAMILY_V6, local)
	if len(got) != 2 || got[0].String() != "::1" || got[1].String() != "2001:db8::1" {
		t.Fatalf("expected the IPv6 local addresses, got %v", got)
	}
}

func TestCandidateDstsMappedSource(t *testing.T) {
	// An IPv4-mapped source resolves to FAMILY_V4, so it must be looked
	// up against the IPv4 local addresses.
	family, _, err := ipFamilyOf(net.ParseIP("::ffff:203.0.113.7"))
	if err != nil || family != netlink.FAMILY_V4 {
		t.Fatalf("ipFamilyOf(mapped) = %v, %v", family, err)
	}
	got := candidateDsts(net.ParseIP("::"), family, []net.IP{net.ParseIP("::1"), net.ParseIP("198.51.100.1")})
	if len(got) != 1 || got[0].String() != "198.51.100.1" {
		t.Fatalf("expected the IPv4 local address, got %v", got)
	}
}
