// Package conntrack marks live TCP connections by 4-tuple through the
// kernel's conntrack table, so packet-mark-based tc/HTB shaping can act
// on them.
package conntrack

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// localAddrsTTL is how long the host's address list is reused for
// wildcard lookups before it is read again.
const localAddrsTTL = 5 * time.Second

// Marker sets a conntrack mark on an existing connection identified by
// its 4-tuple.
type Marker struct {
	log *slog.Logger
	// sockets holds idle netlink sockets for reuse, so a SetMark costs a
	// sendmsg and a recvmsg rather than a socket's whole lifecycle.
	sockets chan *ctSocket

	addrsMu      sync.Mutex
	addrs        []net.IP
	addrsFetched time.Time
}

// NewMarker creates a Marker using the default network namespace.
func NewMarker(log *slog.Logger) *Marker {
	if log == nil {
		log = slog.Default()
	}
	return &Marker{log: log, sockets: make(chan *ctSocket, socketPoolSize)}
}

// SetMark finds the conntrack entry (or entries) matching the given
// source 4-tuple, and updates their mark. proto is currently limited to
// "tcp".
//
// Each lookup is a ctnetlink update keyed by the exact original tuple,
// which the kernel resolves with a hash lookup. All of a call's lookups go
// to the kernel in one sendmsg on a reused socket. SetMark never
// dumps the conntrack table: on a busy host that table holds hundreds of
// thousands of entries, and dumping it per webhook costs far more CPU and
// memory than the shaping is worth.
//
// dstIP for which net.IP.IsUnspecified() holds (0.0.0.0 / ::) is treated
// as "destination unknown": SetMark tries every address assigned to a
// local interface in the source IP's family, and marks every flow found
// rather than picking one or skipping. More than one can legitimately
// match (e.g. a multi-homed host, where a client can hold simultaneous
// connections to two different local IPs while reusing the same source
// port — the OS only requires the full 5-tuple to be unique, not the
// source half alone). See the Marker interface doc in internal/webhook
// and the README for why callers may hand in an unspecified dstIP at
// all. A flow whose local address isn't assigned to an interface (AnyIP
// routes, TPROXY) can't be found this way. A non-wildcard dstIP is
// always required to match exactly, since it plus the rest of the tuple
// is already unique.
//
// SetMark logs a warning whenever more than one flow matches, so an
// unexpectedly frequent occurrence of this on a given deployment is
// visible rather than silent.
func (m *Marker) SetMark(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) error {
	protoNum, err := protocolNumber(proto)
	if err != nil {
		return err
	}

	family, srcIP, err := ipFamilyOf(srcIP)
	if err != nil {
		return err
	}

	var local []net.IP
	if dstIP.IsUnspecified() {
		if local, err = m.localAddrs(); err != nil {
			return fmt.Errorf("listing local addresses: %w", err)
		}
	}

	dsts := candidateDsts(dstIP, family, local)
	reqs := make([]*nl.NetlinkRequest, len(dsts))
	for i, dst := range dsts {
		reqs[i] = markRequest(uint8(family), protoNum, srcIP, srcPort, dst, dstPort, mark)
	}

	marked := 0
	if len(reqs) > 0 {
		sock, err := m.getSocket()
		if err != nil {
			return fmt.Errorf("opening netlink socket: %w", err)
		}
		results, err := sock.exchange(reqs)
		if err != nil {
			sock.close()
			return err
		}
		m.putSocket(sock)
		for _, err := range results {
			switch {
			case err == nil:
				marked++
			case !errNoEntry(err):
				return fmt.Errorf("updating conntrack mark: %w", err)
			}
		}
	}

	if marked == 0 {
		return fmt.Errorf("no conntrack entry for %s %s:%d -> %s:%d", proto, srcIP, srcPort, dstIP, dstPort)
	}
	if marked > 1 {
		m.log.Warn("multiple conntrack entries matched an unknown destination IP; marking all of them (host may be multi-homed and Xray reported an unusable destination address for this connection) — if these are two different real connections rather than the same user's own two connections, they will now briefly share this bandwidth class",
			"proto", proto, "src_ip", srcIP, "src_port", srcPort, "dst_port", dstPort, "match_count", marked)
	}
	return nil
}

// localAddrs returns the addresses assigned to this namespace's
// interfaces, re-reading them at most once per localAddrsTTL.
func (m *Marker) localAddrs() ([]net.IP, error) {
	m.addrsMu.Lock()
	defer m.addrsMu.Unlock()
	if m.addrs != nil && time.Since(m.addrsFetched) < localAddrsTTL {
		return m.addrs, nil
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok {
			ips = append(ips, ipNet.IP)
		}
	}
	m.addrs, m.addrsFetched = ips, time.Now()
	return ips, nil
}

// candidateDsts returns the destination IPs to look up: dstIP itself when
// it is specified, otherwise every address in local of the given family.
// IPs come back in the 4- or 16-byte form ctnetlink expects for family.
func candidateDsts(dstIP net.IP, family netlink.InetFamily, local []net.IP) []net.IP {
	if !dstIP.IsUnspecified() {
		if f, ip, err := ipFamilyOf(dstIP); err == nil && f == family {
			return []net.IP{ip}
		}
		return nil
	}

	var dsts []net.IP
	for _, ip := range local {
		if f, ip, err := ipFamilyOf(ip); err == nil && f == family {
			dsts = append(dsts, ip)
		}
	}
	return dsts
}

func protocolNumber(proto string) (uint8, error) {
	switch proto {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", proto)
	}
}

func ipFamilyOf(ip net.IP) (netlink.InetFamily, net.IP, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return netlink.FAMILY_V4, ip4, nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		return netlink.FAMILY_V6, ip16, nil
	}
	return 0, nil, fmt.Errorf("invalid IP %s", ip)
}
