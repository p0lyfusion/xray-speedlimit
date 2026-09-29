package webhook

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// provisionQueueSize bounds how many marks can wait for provisioning. A
// mark that doesn't fit is queued again by its next webhook.
const provisionQueueSize = 16384

// Marker marks a live connection so downstream enforcement (e.g. tc/HTB)
// can act on it. Handler passes dstIP straight through from Xray-core's
// InboundLocal, which is unreliable for some inbound/transport
// combinations and reports the address-family wildcard (0.0.0.0 / ::)
// instead of the real local IP — see conntrack.Marker's
// implementation for why that's a known, tolerated shape of input, not
// invalid data callers need to filter out first.
type Marker interface {
	SetMark(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) error
}

// RateSetter applies a bandwidth cap to a mark (e.g. by creating/updating
// its tc/HTB class) and reports which marks already have one.
// limiter.Store satisfies this. Handler calls Get on every webhook, so it
// must not wait on the kernel, and Set only for marks with no rate, from
// a background worker.
type RateSetter interface {
	Set(mark uint32, rateBytesPerSec uint32) error
	Get(mark uint32) (rateBytesPerSec uint32, ok bool)
}

// event mirrors the subset of xray-core's app/router webhook payload
// (see app/router/webhook.go, type event) that is needed to mark the
// client's inbound connection.
type event struct {
	Email        *string `json:"email"`
	Network      *string `json:"network"`
	Source       *string `json:"source"`
	InboundLocal *string `json:"inboundLocal"`
}

// Handler receives xray-core webhook POSTs and applies a conntrack mark
// to the client connection they describe.
type Handler struct {
	users                  *Users
	marker                 Marker
	rate                   RateSetter
	perUserRateBytesPerSec uint32
	recent                 *recentMarks
	log                    *slog.Logger

	// queued records marks waiting in provisionQueue (mark -> struct{}),
	// so a mark is queued at most once at a time.
	queued sync.Map
	// provisionQueue feeds provisionLoop.
	provisionQueue chan uint32
}

// New creates a webhook Handler. If rate is non-nil, every mark seen that
// has no rate yet is provisioned with a perUserRateBytesPerSec cap via
// rate.Set, so per-user limits apply uniformly without any external
// provisioning step. Pass a nil rate to manage rates by hand instead
// (e.g. via the HTTP API).
//
// A connection marked less than remarkAfter ago isn't marked again when
// another webhook for it arrives (see recentMarks); 0 marks on every
// webhook.
func New(users *Users, marker Marker, rate RateSetter, perUserRateBytesPerSec uint32, remarkAfter time.Duration, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{
		users:                  users,
		marker:                 marker,
		rate:                   rate,
		perUserRateBytesPerSec: perUserRateBytesPerSec,
		recent:                 newRecentMarks(remarkAfter),
		log:                    log,
	}
	if rate != nil {
		h.provisionQueue = make(chan uint32, provisionQueueSize)
		go h.provisionLoop()
	}
	return h
}

// queueProvision hands mark to provisionLoop unless it already has a rate
// or is already waiting. Provisioning runs in the background, and the
// send never blocks, because tc is slow and marking must not wait for it.
// A mark whose Set failed, or that didn't fit in the queue, is queued
// again by its next webhook. Until its class exists, a marked flow rides
// its queue's default class.
func (h *Handler) queueProvision(mark uint32) {
	if _, ok := h.rate.Get(mark); ok {
		return
	}
	if _, loaded := h.queued.LoadOrStore(mark, struct{}{}); loaded {
		return
	}
	select {
	case h.provisionQueue <- mark:
	default:
		h.queued.Delete(mark)
	}
}

// provisionLoop applies the per-user rate to each queued mark, one at a
// time.
func (h *Handler) provisionLoop() {
	for mark := range h.provisionQueue {
		if err := h.rate.Set(mark, h.perUserRateBytesPerSec); err != nil {
			h.log.Error("webhook: failed to provision per-user rate", "mark", mark, "error", err)
		}
		h.queued.Delete(mark)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ev event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		http.Error(w, "invalid webhook payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if ev.Network != nil && *ev.Network != "" && *ev.Network != "tcp" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if ev.Email == nil || ev.Source == nil || ev.InboundLocal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	src, err := parseAddrPort(*ev.Source)
	if err != nil {
		h.log.Warn("webhook: unparsable source", "source", *ev.Source, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	dst, err := parseAddrPort(*ev.InboundLocal)
	if err != nil {
		h.log.Warn("webhook: unparsable inboundLocal", "inboundLocal", *ev.InboundLocal, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	mark := h.users.Mark(*ev.Email)
	if mark == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.rate != nil {
		h.queueProvision(mark)
	}

	conn := markedConn{src: src, dst: dst, mark: mark}
	if h.recent.contains(conn) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := h.marker.SetMark("tcp", net.IP(src.Addr().AsSlice()), src.Port(), net.IP(dst.Addr().AsSlice()), dst.Port(), mark); err != nil {
		h.log.Error("webhook: failed to set conntrack mark", "email", *ev.Email, "mark", mark, "error", err)
		http.Error(w, "failed to set conntrack mark", http.StatusInternalServerError)
		return
	}
	h.recent.add(conn)

	// Xray ignores the response body.
	w.WriteHeader(http.StatusNoContent)
}

// parseAddrPort parses xray-core's "ip:port" address fields, which it
// builds with net.JoinHostPort. IPv4-mapped IPv6 addresses come back as
// IPv4, so the same connection always gives the same recentMarks key.
func parseAddrPort(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}
