package conntrack

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tcpListen is TCP_LISTEN from the kernel's tcp_states.h.
const tcpListen = 10

// maxDiagSamples caps how many sockets or flows a diagnosis lists.
const maxDiagSamples = 5

// Diagnosis is what the kernel knows about a connection SetMark couldn't
// find, gathered right after the miss so the connection is most likely
// still alive.
type Diagnosis struct {
	// Hint is a one-line reading of the fields below.
	Hint string

	// ClientSockets are TCP sockets in this namespace whose remote end is
	// the client's exact IP:port.
	ClientSockets []string
	// Listening reports whether anything listens on the destination port
	// in this namespace.
	Listening bool
	// PeersOnPort samples the remote ends of established sockets on the
	// destination port, and PeersOnPortCount counts them all.
	PeersOnPort      []string
	PeersOnPortCount int

	// ConntrackTotal is the number of entries in this family's
	// conntrack table.
	ConntrackTotal int
	// ClientFlows are conntrack entries from the client's IP, on any port.
	ClientFlows []string

	// NetNS and InitNetNS identify this process's network namespace and
	// PID 1's (the host's, unless the service has its own PID namespace).
	NetNS, InitNetNS string
}

// DiagnoseMiss runs Diagnose and returns the result as slog key/value
// pairs. It is what webhook.MissDiagnoser calls.
func (m *Marker) DiagnoseMiss(srcIP net.IP, srcPort, dstPort uint16) ([]any, error) {
	d, err := m.Diagnose(srcIP, srcPort, dstPort)
	return d.Attrs(), err
}

// Attrs returns d as slog key/value pairs.
func (d Diagnosis) Attrs() []any {
	return []any{
		"hint", d.Hint,
		"client_sockets", d.ClientSockets,
		"listening_on_port", d.Listening,
		"peers_on_port_count", d.PeersOnPortCount,
		"peers_on_port_sample", d.PeersOnPort,
		"conntrack_total", d.ConntrackTotal,
		"conntrack_flows_from_client_ip", d.ClientFlows,
		"netns", d.NetNS,
		"init_netns", d.InitNetNS,
	}
}

// Diagnose looks for the connection SetMark missed from two sides: the
// kernel's TCP sockets and the conntrack table. It dumps both, so it is
// far too expensive to run per webhook; callers must rate-limit it.
func (m *Marker) Diagnose(srcIP net.IP, srcPort uint16, dstPort uint16) (Diagnosis, error) {
	family, srcIP, err := ipFamilyOf(srcIP)
	if err != nil {
		return Diagnosis{}, err
	}

	var d Diagnosis
	d.NetNS, _ = os.Readlink("/proc/self/ns/net")
	d.InitNetNS, _ = os.Readlink("/proc/1/ns/net")

	// Xray usually listens on "::", in which case IPv4 clients show up on
	// AF_INET6 sockets as v4-mapped addresses, so both families are
	// searched. net.IP.Equal treats the two forms as equal.
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		socks, err := netlink.SocketDiagTCP(fam)
		if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
			return d, fmt.Errorf("listing TCP sockets: %w", err)
		}
		for _, s := range socks {
			id := s.ID
			if id.SourcePort != dstPort {
				continue
			}
			if s.State == tcpListen {
				d.Listening = true
				continue
			}
			if id.Destination.Equal(srcIP) && id.DestinationPort == srcPort {
				d.ClientSockets = append(d.ClientSockets, fmt.Sprintf("%s -> %s state=%d",
					hostPort(id.Destination, id.DestinationPort), hostPort(id.Source, id.SourcePort), s.State))
			}
			d.PeersOnPortCount++
			if len(d.PeersOnPort) < maxDiagSamples {
				d.PeersOnPort = append(d.PeersOnPort, hostPort(id.Destination, id.DestinationPort))
			}
		}
	}

	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return d, fmt.Errorf("listing conntrack table: %w", err)
	}
	d.ConntrackTotal = len(flows)
	for _, f := range flows {
		if f.Forward.Protocol != unix.IPPROTO_TCP || !f.Forward.SrcIP.Equal(srcIP) {
			continue
		}
		if len(d.ClientFlows) < maxDiagSamples {
			d.ClientFlows = append(d.ClientFlows, fmt.Sprintf("%s -> %s reply %s -> %s mark=%d",
				hostPort(f.Forward.SrcIP, f.Forward.SrcPort), hostPort(f.Forward.DstIP, f.Forward.DstPort),
				hostPort(f.Reverse.SrcIP, f.Reverse.SrcPort), hostPort(f.Reverse.DstIP, f.Reverse.DstPort), f.Mark))
		}
	}

	d.Hint = hint(d)
	return d, nil
}

func hint(d Diagnosis) string {
	switch {
	case d.ConntrackTotal == 0:
		return "the conntrack table in this network namespace is empty: nothing is being tracked here (wrong namespace, or tracking not enabled)"
	case len(d.ClientSockets) > 0 && len(d.ClientFlows) == 0:
		return "the kernel has this TCP connection but conntrack has nothing from the client's IP: the connection is untracked (look for a notrack rule)"
	case len(d.ClientSockets) > 0:
		return "the kernel has this TCP connection and conntrack has flows from the client's IP, but not with this tuple (NAT, or a different port): compare conntrack_flows_from_client_ip"
	case !d.Listening:
		return "nothing listens on the destination port in this network namespace: the service is not in Xray's namespace"
	case len(d.ClientFlows) > 0:
		return "no TCP socket from this client IP:port, but conntrack has flows from its IP: compare conntrack_flows_from_client_ip"
	default:
		return "no TCP socket or conntrack flow from this client here: the address Xray reported is not the TCP peer (a proxy, CDN, PROXY protocol or X-Forwarded-For in front of Xray?); see peers_on_port_sample"
	}
}

func hostPort(ip net.IP, port uint16) string {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return net.JoinHostPort(ip.String(), fmt.Sprint(port))
}
