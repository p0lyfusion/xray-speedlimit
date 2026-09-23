// Package conntrack marks live TCP connections by 4-tuple through the
// kernel's conntrack table, so packet-mark-based tc/HTB shaping can act
// on them.
package conntrack

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Marker sets a conntrack mark on an existing connection identified by
// its 4-tuple.
type Marker struct {
	log *slog.Logger
}

// NewMarker creates a Marker using the default network namespace.
func NewMarker(log *slog.Logger) *Marker {
	if log == nil {
		log = slog.Default()
	}
	return &Marker{log: log}
}

// SetMark finds the conntrack entry (or entries) matching the given
// source 4-tuple, and updates their mark. proto is currently limited to
// "tcp".
//
// dstIP for which net.IP.IsUnspecified() holds (0.0.0.0 / ::) is treated
// as "destination unknown": the flow is matched on source 4-tuple plus
// destination port alone, which can legitimately return more than one
// flow (e.g. a multi-homed host, where a client can hold simultaneous
// connections to two different local IPs while reusing the same source
// port — the OS only requires the full 5-tuple to be unique, not the
// source half alone). SetMark marks every matching flow rather than
// picking one or skipping — see the Marker interface doc in
// internal/webhook and the README for why callers may hand in an
// unspecified dstIP at all, and why marking every match is the correct
// (not merely safe) response to that ambiguity. A non-wildcard dstIP is
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

	matchDstIP := dstIP
	if dstIP.IsUnspecified() {
		matchDstIP = nil
	}

	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return fmt.Errorf("listing conntrack table: %w", err)
	}

	matches := findFlows(flows, protoNum, srcIP, srcPort, matchDstIP, dstPort)
	if len(matches) == 0 {
		return fmt.Errorf("no conntrack entry for %s %s:%d -> %s:%d", proto, srcIP, srcPort, dstIP, dstPort)
	}
	if len(matches) > 1 {
		m.log.Warn("multiple conntrack entries matched an unknown destination IP; marking all of them (host may be multi-homed and Xray reported an unusable destination address for this connection) — if these are two different real connections rather than the same user's own two connections, they will now briefly share this bandwidth class",
			"proto", proto, "src_ip", srcIP, "src_port", srcPort, "dst_port", dstPort, "match_count", len(matches))
	}

	for _, flow := range matches {
		flow.Mark = mark
		if err := netlink.ConntrackUpdate(netlink.ConntrackTable, family, flow); err != nil {
			return fmt.Errorf("updating conntrack mark: %w", err)
		}
	}
	return nil
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

// findFlows returns every flow matching proto/srcIP/srcPort/dstPort. If
// dstIP is non-nil, a flow must also match it exactly — in which case at
// most one result is possible, since a real dstIP plus the rest of the
// tuple is always unique, so the scan stops at that first (and only)
// match rather than continuing over the rest of the table. More than one
// result is only possible, and the full table gets scanned, when dstIP is
// nil.
func findFlows(flows []*netlink.ConntrackFlow, proto uint8, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) []*netlink.ConntrackFlow {
	var matches []*netlink.ConntrackFlow
	for _, f := range flows {
		fwd := f.Forward
		if fwd.Protocol != proto || fwd.SrcPort != srcPort || fwd.DstPort != dstPort || !fwd.SrcIP.Equal(srcIP) {
			continue
		}
		if dstIP != nil {
			if fwd.DstIP.Equal(dstIP) {
				return []*netlink.ConntrackFlow{f}
			}
			continue
		}
		matches = append(matches, f)
	}
	return matches
}
