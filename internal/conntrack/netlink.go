package conntrack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	// socketPoolSize is how many idle netlink sockets a Marker keeps for
	// reuse. More SetMark calls than this can run at once; the extras
	// open a socket and close it afterwards.
	socketPoolSize = 8
	// replyTimeout bounds how long a batch waits for its acks.
	replyTimeout = 2 * time.Second
)

// ctSocket is a NETLINK_NETFILTER socket used for one batch at a time.
type ctSocket struct {
	fd  int
	buf []byte
}

func newCTSocket() (*ctSocket, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	tv := unix.NsecToTimeval(replyTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// Acks for failed requests then leave out the request itself, which
	// keeps a batch's replies small. Older kernels lack it; that's fine.
	_ = unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_CAP_ACK, 1)
	return &ctSocket{fd: fd, buf: make([]byte, 64*1024)}, nil
}

func (s *ctSocket) close() {
	unix.Close(s.fd)
}

// getSocket returns an idle pooled socket, or a new one.
func (m *Marker) getSocket() (*ctSocket, error) {
	select {
	case s := <-m.sockets:
		return s, nil
	default:
		return newCTSocket()
	}
}

// putSocket returns s to the pool, or closes it if the pool is full.
func (m *Marker) putSocket(s *ctSocket) {
	select {
	case m.sockets <- s:
	default:
		s.close()
	}
}

// exchange sends reqs in one sendmsg and waits for each one's ack. It
// returns each request's result: nil, or the errno the kernel answered
// with. A socket that failed mid-exchange may still get late replies, so
// the caller must close it rather than reuse it when err != nil.
func (s *ctSocket) exchange(reqs []*nl.NetlinkRequest) (results []error, err error) {
	index := make(map[uint32]int, len(reqs))
	var batch []byte
	for i, req := range reqs {
		index[req.Seq] = i
		batch = append(batch, req.Serialize()...)
	}
	if err := unix.Sendto(s.fd, batch, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("sending conntrack updates: %w", err)
	}

	results = make([]error, len(reqs))
	pending := len(reqs)
	for pending > 0 {
		n, _, err := unix.Recvfrom(s.fd, s.buf, 0)
		if err != nil {
			return nil, fmt.Errorf("reading conntrack replies: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(s.buf[:n])
		if err != nil {
			return nil, fmt.Errorf("parsing conntrack replies: %w", err)
		}
		for _, msg := range msgs {
			i, ok := index[msg.Header.Seq]
			if !ok || msg.Header.Type != unix.NLMSG_ERROR || len(msg.Data) < 4 {
				continue
			}
			delete(index, msg.Header.Seq)
			pending--
			if errno := -int32(binary.NativeEndian.Uint32(msg.Data[:4])); errno != 0 {
				results[i] = unix.Errno(errno)
			}
		}
	}
	return results, nil
}

// markRequest builds a ctnetlink update that sets mark on the conntrack
// entry whose original tuple is exactly the one given. It carries only
// the tuple and CTA_MARK, so the kernel leaves every other attribute
// alone, and a miss is answered with ENOENT. netlink.ConntrackUpdate
// isn't used because it always sends CTA_TIMEOUT and the reply tuple,
// which would need a dump to fill in. NLM_F_CREATE is left out so a miss
// can't insert an entry.
func markRequest(family uint8, proto uint8, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) *nl.NetlinkRequest {
	srcAttr, dstAttr := nl.CTA_IP_V4_SRC, nl.CTA_IP_V4_DST
	if family == unix.AF_INET6 {
		srcAttr, dstAttr = nl.CTA_IP_V6_SRC, nl.CTA_IP_V6_DST
	}

	tupleIP := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_IP, nil)
	tupleIP.AddChild(nl.NewRtAttr(srcAttr, srcIP))
	tupleIP.AddChild(nl.NewRtAttr(dstAttr, dstIP))

	tupleProto := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_PROTO, nil)
	tupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_NUM, []byte{proto}))
	tupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_SRC_PORT, nl.BEUint16Attr(srcPort)))
	tupleProto.AddChild(nl.NewRtAttr(nl.CTA_PROTO_DST_PORT, nl.BEUint16Attr(dstPort)))

	tupleOrig := nl.NewRtAttr(unix.NLA_F_NESTED|nl.CTA_TUPLE_ORIG, nil)
	tupleOrig.AddChild(tupleIP)
	tupleOrig.AddChild(tupleProto)

	req := nl.NewNetlinkRequest(int(netlink.ConntrackTable)<<8|nl.IPCTNL_MSG_CT_NEW, unix.NLM_F_ACK)
	req.AddData(&nl.Nfgenmsg{NfgenFamily: family, Version: nl.NFNETLINK_V0})
	req.AddData(tupleOrig)
	req.AddData(nl.NewRtAttr(nl.CTA_MARK, nl.BEUint32Attr(mark)))
	return req
}

// errNoEntry reports whether err is the kernel's answer for a tuple with
// no conntrack entry.
func errNoEntry(err error) bool {
	return errors.Is(err, unix.ENOENT)
}
