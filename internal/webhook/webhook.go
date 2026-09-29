package webhook

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// missDiagnoseInterval is the minimum gap between two diagnoses of a
// connection the Marker couldn't mark. Each one dumps kernel tables.
const missDiagnoseInterval = 30 * time.Second

// Marker marks a live connection so downstream enforcement (e.g. tc/HTB)
// can act on it. Handler passes dstIP straight through from Xray-core's
// InboundLocal (see parseHostPort below), which is unreliable for some
// inbound/transport combinations and reports the address-family wildcard
// (0.0.0.0 / ::) instead of the real local IP — see conntrack.Marker's
// implementation for why that's a known, tolerated shape of input, not
// invalid data callers need to filter out first.
type Marker interface {
	SetMark(proto string, srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, mark uint32) error
}

// MissDiagnoser is optionally implemented by a Marker that can explain
// why SetMark found nothing. DiagnoseMiss is expensive, so Handler calls
// it at most once per missDiagnoseInterval, in the background, right
// after a failure so the connection is most likely still alive. It
// returns slog key/value pairs.
type MissDiagnoser interface {
	DiagnoseMiss(srcIP net.IP, srcPort, dstPort uint16) ([]any, error)
}

// RateSetter applies a bandwidth cap to a mark (e.g. by creating/updating
// its tc/HTB class). limiter.Store satisfies this. Handler calls it once
// per mark, from a background worker, not on every webhook, since
// implementations reconfigure real kernel state on each call.
type RateSetter interface {
	Set(mark uint32, rateBytesPerSec uint32) error
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
	alloc                  *Allocator
	marker                 Marker
	rate                   RateSetter
	perUserRateBytesPerSec uint32
	log                    *slog.Logger

	// provisioned records marks whose rate.Set has succeeded (mark ->
	// struct{}).
	provisioned sync.Map
	// queued records marks waiting in provisionQueue (mark -> struct{}),
	// so a mark is queued at most once at a time.
	queued sync.Map
	// provisionQueue feeds provisionLoop. It holds one slot per mark the
	// allocator can hand out, so a send never blocks.
	provisionQueue chan uint32

	// lastDiagnose is when the last miss diagnosis started, in Unix
	// nanoseconds.
	lastDiagnose atomic.Int64
}

// New creates a webhook Handler. If rate is non-nil, every newly
// allocated mark is provisioned with a perUserRateBytesPerSec cap via
// rate.Set, so per-user limits apply uniformly without any external
// provisioning step. Pass a nil rate to manage rates by hand instead
// (e.g. via the HTTP API).
func New(alloc *Allocator, marker Marker, rate RateSetter, perUserRateBytesPerSec uint32, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{
		alloc:                  alloc,
		marker:                 marker,
		rate:                   rate,
		perUserRateBytesPerSec: perUserRateBytesPerSec,
		log:                    log,
	}
	if rate != nil {
		h.provisionQueue = make(chan uint32, alloc.count)
		go h.provisionLoop()
	}
	return h
}

// queueProvision hands mark to provisionLoop unless its rate is already
// set or it is already waiting. Provisioning runs in the background
// because it can be slow: rate.Set shells out to tc, which takes tens of
// milliseconds per call on a host with thousands of classes. After a
// restart every active user is new again, and when webhooks waited for
// that in turn, they reached SetMark minutes late, after short
// connections had closed. Until its class exists, a marked flow rides
// the default class.
//
// This is called on every webhook for the mark, so a mark whose rate.Set
// failed is queued again by its next webhook: the allocator's isNew
// fires only once, whether or not provisioning then succeeds.
func (h *Handler) queueProvision(mark uint32) {
	if _, ok := h.provisioned.Load(mark); ok {
		return
	}
	if _, loaded := h.queued.LoadOrStore(mark, struct{}{}); loaded {
		return
	}
	h.provisionQueue <- mark
}

// provisionLoop applies the per-user rate to each queued mark, one at a
// time.
func (h *Handler) provisionLoop() {
	for mark := range h.provisionQueue {
		if err := h.rate.Set(mark, h.perUserRateBytesPerSec); err != nil {
			h.log.Error("webhook: failed to provision per-user rate", "mark", mark, "error", err)
		} else {
			h.provisioned.Store(mark, struct{}{})
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

	srcIP, srcPort, err := parseHostPort(*ev.Source)
	if err != nil {
		h.log.Warn("webhook: unparsable source", "source", *ev.Source, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	dstIP, dstPort, err := parseHostPort(*ev.InboundLocal)
	if err != nil {
		h.log.Warn("webhook: unparsable inboundLocal", "inboundLocal", *ev.InboundLocal, "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	mark, _ := h.alloc.Allocate(*ev.Email)
	if mark == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if h.rate != nil {
		h.queueProvision(mark)
	}

	if err := h.marker.SetMark("tcp", srcIP, srcPort, dstIP, dstPort, mark); err != nil {
		h.log.Error("webhook: failed to set conntrack mark", "email", *ev.Email, "mark", mark, "error", err)
		h.maybeDiagnose(*ev.Email, *ev.Source, srcIP, srcPort, dstPort)
		http.Error(w, "failed to set conntrack mark", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Email string `json:"email"`
		Mark  uint32 `json:"mark"`
	}{Email: *ev.Email, Mark: mark})
}

// maybeDiagnose starts a background diagnosis of a failed mark if the
// marker supports it and none has started in the last
// missDiagnoseInterval.
func (h *Handler) maybeDiagnose(email, source string, srcIP net.IP, srcPort, dstPort uint16) {
	d, ok := h.marker.(MissDiagnoser)
	if !ok {
		return
	}
	now := time.Now().UnixNano()
	last := h.lastDiagnose.Load()
	if now-last < int64(missDiagnoseInterval) || !h.lastDiagnose.CompareAndSwap(last, now) {
		return
	}
	go func() {
		attrs, err := d.DiagnoseMiss(srcIP, srcPort, dstPort)
		if err != nil {
			h.log.Warn("webhook: diagnosing unmarked connection failed", "source", source, "error", err)
			return
		}
		h.log.Warn("webhook: diagnosis of unmarked connection",
			append([]any{"email", email, "source", source, "dst_port", dstPort}, attrs...)...)
	}()
}

// parseHostPort parses xray-core's "ip:port" address fields. It also
// tolerates an optional "proto:" prefix (as used by net.Destination's
// String() elsewhere in xray-core) in case a differently-shaped address
// ends up in these fields.
func parseHostPort(s string) (net.IP, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	var ip net.IP
	if err == nil {
		ip = net.ParseIP(host)
	}

	if ip == nil {
		if idx := strings.IndexByte(s, ':'); idx >= 0 && idx+1 < len(s) {
			if h2, p2, err2 := net.SplitHostPort(s[idx+1:]); err2 == nil {
				if ip2 := net.ParseIP(h2); ip2 != nil {
					host, portStr, ip, err = h2, p2, ip2, nil
				}
			}
		}
	}

	if ip == nil {
		if err == nil {
			err = fmt.Errorf("invalid address %q", s)
		}
		return nil, 0, err
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid port in %q: %w", s, err)
	}
	return ip, uint16(port), nil
}
